//! Hashing and Merkle primitives.
//!
//! Every hash is domain-separated with a single tag byte so that a leaf can
//! never be reinterpreted as an internal node, a nullifier as a commitment,
//! and so on. Client SDKs must reproduce these derivations exactly, and the
//! contract exposes them as view functions (`derive_leaf`, `derive_nullifier`,
//! `derive_commitment`) so nobody has to reimplement them.

use soroban_sdk::{Bytes, BytesN, Env, Vec};

const TAG_NODE: u8 = 0x01;
/// Reserved 0x02, 0x03 for future leaf variants.
const TAG_LEAF: u8 = 0x04;
const TAG_NULLIFIER: u8 = 0x05;
const TAG_COMMITMENT: u8 = 0x06;

fn sha256(env: &Env, buf: &Bytes) -> BytesN<32> {
    let digest = env.crypto().sha256(buf);
    BytesN::from_array(env, &digest.to_array())
}

fn tagged(env: &Env, tag: u8, parts: &[Bytes]) -> BytesN<32> {
    let mut buf = Bytes::from_array(env, &[tag]);
    for part in parts.iter() {
        buf.append(part);
    }
    sha256(env, &buf)
}

fn be32(env: &Env, v: u32) -> Bytes {
    Bytes::from_array(env, &v.to_be_bytes())
}

fn be64(env: &Env, v: u64) -> Bytes {
    Bytes::from_array(env, &v.to_be_bytes())
}

fn as_bytes(env: &Env, v: &BytesN<32>) -> Bytes {
    Bytes::from_array(env, &v.to_array())
}

/// Internal Merkle node: `H(0x01 || left || right)`.
pub fn node_hash(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    tagged(env, TAG_NODE, &[as_bytes(env, left), as_bytes(env, right)])
}

/// Anonymous credential leaf: `H(0x04 || secret || salt)`.
///
/// `secret` is generated and held by the student; `salt` is a per-issuance
/// randomiser. The issuer should retain only the resulting Merkle root (see the
/// credential custody rule in the README).
pub fn derive_leaf(env: &Env, secret: &BytesN<32>, salt: &BytesN<32>) -> BytesN<32> {
    tagged(env, TAG_LEAF, &[as_bytes(env, secret), as_bytes(env, salt)])
}

/// One-time report tag: `H(0x05 || leaf || epoch)`.
///
/// Deterministic per (credential, epoch) so a student can file exactly one
/// report per epoch, while being unlinkable to the credential itself unless the
/// leaf is disclosed.
pub fn derive_nullifier(env: &Env, leaf: &BytesN<32>, epoch: u32) -> BytesN<32> {
    tagged_cpi(env, TAG_NULLIFIER, leaf, epoch)
}

fn tagged_cpi(env: &Env, tag: u8, leaf: &BytesN<32>, epoch: u32) -> BytesN<32> {
    tagged(env, tag, &[as_bytes(env, leaf), be32(env, epoch)])
}

/// Report commitment:
/// `H(0x06 || leaf || nullifier || symptom || zone_id || geocell || epoch)`.
///
/// Binds every disclosed field to the credential that produced the report, so
/// the commitment cannot be replayed with different contents.
#[allow(clippy::too_many_arguments)]
pub fn derive_commitment(
    env: &Env,
    leaf: &BytesN<32>,
    nullifier: &BytesN<32>,
    symptom: u32,
    zone_id: u32,
    geocell: u64,
    epoch: u32,
) -> BytesN<32> {
    tagged(
        env,
        TAG_COMMITMENT,
        &[
            as_bytes(env, leaf),
            as_bytes(env, nullifier),
            be32(env, symptom),
            be32(env, zone_id),
            be64(env, geocell),
            be32(env, epoch),
        ],
    )
}

/// Index-addressed Merkle inclusion check.
///
/// Leaves are inserted left to right; bit `i` of `index` selects whether the
/// sibling at depth `i` is on the right (0) or the left (1) of the running node.
pub fn verify_merkle(
    env: &Env,
    leaf: &BytesN<32>,
    index: u32,
    path: &Vec<BytesN<32>>,
    root: &BytesN<32>,
) -> bool {
    if path.is_empty() {
        // A single-leaf tree: the leaf is the root.
        return leaf == root;
    }

    let mut node = leaf.clone();
    let mut idx = index;

    for sibling in path.iter() {
        if idx & 1 == 0 {
            node = node_hash(env, &node, &sibling);
        } else {
            node = node_hash(env, &sibling, &node);
        }
        idx >>= 1;
    }

    node == *root
}
