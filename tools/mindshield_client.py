#!/usr/bin/env python3
"""Reference client for the MindShield campus epidemiology contract.

This is the off-chain half of the protocol, and it is deliberately dependency
free so an issuer or a student device can run it anywhere. It reproduces the
contract's domain-separated derivations exactly:

    leaf        = sha256(0x04 || credential_secret || issuance_salt)
    nullifier   = sha256(0x05 || leaf || epoch_be32)
    commitment  = sha256(0x06 || leaf || nullifier || symptom_be32
                              || zone_id_be32 || geocell_be64 || epoch_be32)
    node        = sha256(0x01 || left || right)

`enroll` plays the issuer: it builds an anonymous credential set, prints the
Merkle root to install on chain with `rotate_credentials`, and writes each
student's leaf plus inclusion path to a roster file.

`report` plays the student device: it builds the `Report` JSON to hand to a
relayer (or to `stellar contract invoke -- submit_report`).

NOTHING IN THE ROSTER FILE MAY EVER BE PUBLISHED. It maps a leaf to the student
who holds it, which is precisely what the protocol keeps off chain. Deliver each
student their own leaf and path, then delete the roster.

Examples
--------
    # issuer: 8 students, daily epoch
    python3 tools/mindshield_client.py enroll --students 8 --out /tmp/roster.json

    # student device (or relayer) building one shielded report
    python3 tools/mindshield_client.py report \\
        --roster /tmp/roster.json --student 3 \\
        --zone 1 --geocell 10 --symptom 1 --epoch 20714
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

TAG_NODE = 0x01
TAG_LEAF = 0x04
TAG_NULLIFIER = 0x05
TAG_COMMITMENT = 0x06

SYMPTOMS = {
    "fever": 1,
    "respiratory": 2,
    "gastrointestinal": 3,
    "headache": 4,
    "rash": 5,
    "fatigue": 6,
}


def h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def leaf_of(secret: bytes, salt: bytes) -> bytes:
    return h(bytes([TAG_LEAF]), secret, salt)


def nullifier_of(leaf: bytes, epoch: int) -> bytes:
    return h(bytes([TAG_NULLIFIER]), leaf, epoch.to_bytes(4, "big"))


def commitment_of(
    leaf: bytes, nullifier: bytes, symptom: int, zone_id: int, geocell: int, epoch: int
) -> bytes:
    return h(
        bytes([TAG_COMMITMENT]),
        leaf,
        nullifier,
        symptom.to_bytes(4, "big"),
        zone_id.to_bytes(4, "big"),
        geocell.to_bytes(8, "big"),
        epoch.to_bytes(4, "big"),
    )


def node_of(left: bytes, right: bytes) -> bytes:
    return h(bytes([TAG_NODE]), left, right)


def build_tree(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """Return the Merkle root and one inclusion path per leaf.

    Leaves are consumed left to right; the caller must pad to a power of two.
    """
    if not leaves or len(leaves) & (len(leaves) - 1):
        raise ValueError("leaf count must be a power of two")

    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append([node_of(current[i], current[i + 1]) for i in range(0, len(current), 2)])

    paths: list[list[bytes]] = []
    for index in range(len(leaves)):
        path, idx = [], index
        for level in levels[:-1]:
            path.append(level[idx + 1] if idx % 2 == 0 else level[idx - 1])
            idx //= 2
        paths.append(path)
    return levels[-1][0], paths


def cmd_enroll(args: argparse.Namespace) -> int:
    students = args.students
    if students & (students - 1):
        print("error: --students must be a power of two", file=sys.stderr)
        return 2

    # A real issuer takes the secret from the student's device and the salt from
    # a CSPRNG. Deterministic secrets here are for reproducible test runs only.
    secrets = [bytes([i + 1]) * 32 for i in range(students)]
    salt = bytes([args.salt & 0xFF]) * 32
    leaves = [leaf_of(secret, salt) for secret in secrets]
    root, paths = build_tree(leaves)

    roster = {
        "root": root.hex(),
        "epoch_length_secs": args.epoch_length_secs,
        "students": [
            {
                "index": index,
                "leaf": leaves[index].hex(),
                "path": [node.hex() for node in paths[index]],
                # The secret is returned only so this demo roster is
                # self-contained; a real issuer never writes it down.
                "credential_secret": secrets[index].hex(),
            }
            for index in range(students)
        ],
    }

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(roster, handle, indent=2)

    print(f"students    : {students}")
    print(f"merkle root : {root.hex()}")
    print(f"roster      : {args.out}")
    print()
    print("install it on chain with:")
    print(f"  stellar contract invoke --id <CONTRACT_ID> --source <issuer> \\")
    print(f"      -- rotate_credentials --root {root.hex()}")
    print()
    print("keep the roster off chain: it is the only link between a leaf and a student.")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    with open(args.roster, encoding="utf-8") as handle:
        roster = json.load(handle)

    entry = roster["students"][args.student]
    leaf = bytes.fromhex(entry["leaf"])
    nullifier = nullifier_of(leaf, args.epoch)
    commitment = commitment_of(
        leaf, nullifier, args.symptom, args.zone, args.geocell, args.epoch
    )

    report = {
        "zone_id": args.zone,
        "geocell": args.geocell,
        "symptom": args.symptom,
        "epoch": args.epoch,
        "leaf": leaf.hex(),
        "index": entry["index"],
        "path": entry["path"],
        "nullifier": nullifier.hex(),
        "commitment": commitment.hex(),
    }
    print(json.dumps(report, indent=2))

    if not args.quiet:
        print(
            f"\n# file it through a relayer, never from the student's own account:\n"
            f"#   stellar contract invoke --id <CONTRACT_ID> --source <relayer> \\\n"
            f"#       -- submit_report --report '<json above>'",
            file=sys.stderr,
        )
    return 0


def cmd_verify_path(args: argparse.Namespace) -> int:
    """Recompute the root from a leaf and path, to check it locally."""
    node = bytes.fromhex(args.leaf)
    idx = args.index
    for sibling in args.path:
        other = bytes.fromhex(sibling.replace(",", ""))
        node = node_of(node, other) if idx % 2 == 0 else node_of(other, node)
        idx //= 2
    print(node.hex())
    print("matches supplied root" if node.hex() == args.root else "DOES NOT match root", file=sys.stderr)
    return 0 if node.hex() == args.root else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(required=True)

    enroll = sub.add_parser("enroll", help="issuer: build a credential set and print the root")
    enroll.add_argument("--students", type=int, default=8, help="power of two")
    enroll.add_argument("--salt", type=int, default=0xA5, help="demo salt byte")
    enroll.add_argument("--epoch-length-secs", type=int, default=86400)
    enroll.add_argument("--out", default="roster.json")
    enroll.set_defaults(func=cmd_enroll)

    report = sub.add_parser("report", help="student device: build one shielded report")
    report.add_argument("--roster", required=True)
    report.add_argument("--student", type=int, required=True)
    report.add_argument("--zone", type=int, required=True)
    report.add_argument("--geocell", type=int, required=True)
    report.add_argument("--symptom", required=True, help="class code, or one of: " + ", ".join(SYMPTOMS))
    report.add_argument("--epoch", type=int, required=True)
    report.add_argument("--quiet", action="store_true")
    report.set_defaults(func=cmd_report)

    verify = sub.add_parser("verify-path", help="recompute a root from a leaf and path")
    verify.add_argument("--leaf", required=True)
    verify.add_argument("--index", type=int, required=True)
    verify.add_argument("--path", nargs="+", required=True)
    verify.add_argument("--root", required=True)
    verify.set_defaults(func=cmd_verify_path)

    args = parser.parse_args()
    if hasattr(args, "symptom") and isinstance(args.symptom, str):
        args.symptom = SYMPTOMS.get(args.symptom.lower(), args.symptom)
        args.symptom = int(args.symptom)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
