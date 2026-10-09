# MindShield — privacy-preserving campus epidemiology on Soroban

A decentralised epidemiological early-warning protocol. Students submit
cryptographically shielded, geofenced symptom reports; a Soroban smart contract
aggregates them and **automatically raises a campus outbreak alert** when a dorm,
dining hall or faculty building crosses its learned baseline — typically days
before a central lab result confirms anything.

No individual health record is ever created. Nobody, including the health centre
that runs the contract, can read a single student's report out of the chain.

```
   student device                         Soroban network                 health centre
 ┌────────────────┐                    ┌────────────────────┐          ┌────────────────┐
 │ symptom class  │                    │  k-anonymised      │          │  alert feed    │
 │ + coarse cell  │  shielded report   │  counters per      │  alert   │  → dorm water  │
 │ + epoch        │ ─────────────────► │  (epoch, zone,     │ ───────► │  testing,      │
 │ + credential   │   relayed, no      │   symptom)         │  event   │  isolation,    │
 │   Merkle proof │   signature, no    │                    │          │  comms         │
 └────────────────┘   identity          │  baselines, alerts │          └────────────────┘
        ▲                               └────────────────────┘
        │ anonymous credential (leaf + path)
        │
 ┌────────────────┐     issuer keeps only the Merkle root, not the leaf map
 │  credential    │
 │  issuer        │
 └────────────────┘
```

**Status.** Live on Stellar **testnet** at
[`CAULIGUW774GXMSF4SPJJDP5FLTTV42NEGT64ORMOXWDZZA5H35IVNAI`](https://stellar.expert/explorer/testnet/contract/CAULIGUW774GXMSF4SPJJDP5FLTTV42NEGT64ORMOXWDZZA5H35IVNAI),
where the full reporting, alerting and epoch-close flow has been exercised
end to end (§8). 29 tests pass, `cargo clippy -D warnings` and
`cargo fmt --check` are clean, and the deployed wasm is the artifact this
repository builds. No third-party audit, and **no mainnet deployment** — that
needs a funded account and an explicit decision.

---

## 1. What the chain actually stores

An accepted report leaves behind four things, none of which identifies anyone:

| Stored | Key | Lifetime |
| --- | --- | --- |
| One-time nullifier marker `H(0x05 ‖ leaf ‖ epoch)` | `Nullifier(epoch, nullifier)` | deleted by `close_epoch` |
| Live cell counter | `Cell(epoch, zone_id, symptom)` | deleted by `close_epoch` |
| An opaque commitment, in the event log | event `report` | permanent, hash only |
| Alerts and k-anonymised summaries | `Alert(id)`, `EpochSummary(epoch)` | alerts permanent, summaries purgeable |

Never stored, anywhere: an `Address` of a reporter, a student identifier, a
precise coordinate, free text, or the credential leaf that proves eligibility.
The contract is deployed without any `require_auth` on the reporting path, so a
report carries **no signature at all** and can be submitted by a relayer.

Derivations, all domain-separated so a value can never be reinterpreted as a
different kind of value:

```
leaf        = H(0x04 ‖ credential_secret ‖ issuance_salt)
nullifier   = H(0x05 ‖ leaf ‖ epoch)
commitment  = H(0x06 ‖ leaf ‖ nullifier ‖ symptom ‖ zone_id ‖ geocell ‖ epoch)
node        = H(0x01 ‖ left ‖ right)            // Merkle interior node
```

## 2. Privacy mechanisms

1. **Eligibility without identity.** The issuer builds a Merkle tree over
   anonymous credential leaves and calls `rotate_credentials(root)`. A report
   carries `leaf`, `index` and a `path`; the contract verifies inclusion against
   the live root. The chain learns *"an enrolled student"*, never *which one*.
2. **One credential, one report per epoch.** `nullifier = H(leaf ‖ epoch)` is
   consumed on acceptance, so a credential cannot be counted twice in an epoch.
   This is per credential and per epoch, **not per cell**: one student cannot
   file for ten dorms to manufacture a spike.
3. **Coarse geofencing.** Reports bind to a registered `zone_id` and a coarse
   `geocell` that must be on that zone's allow-list, so a precise location cannot
   be smuggled on chain. Symptom input is a bounded class code (`1..=32`), never
   free text.
4. **k-anonymity on every read path.** `cell_reading` and `summary` return
   `Visible(n)` only for `n >= k_anon`; below that they return `Suppressed` or
   `Empty`. There is no read function that can leak a sub-`k` count, including
   `submit_report`'s own return value.
5. **Transient raw telemetry.** `close_epoch` folds each cell into its baseline,
   then *deletes* the raw counters and that epoch's nullifier markers. Only
   aggregates that cleared the `k` threshold survive, as `EpochSummary`.
   `purge_summary` applies the health centre's retention policy afterwards.
6. **Voluntary disclosure only.** `verify_disclosure(report)` lets a student hand
   a report back to a counsellor and have the contract confirm
   `credential_valid` / `nullifier_bound` / `commitment_bound` /
   `nullifier_used`. Nobody can be forced to disclose, and no third party can
   prove a report belongs to someone else.

## 3. Outbreak detection

Each accepted report re-evaluates its cell immediately, mid-epoch:

```
epoch            = floor(ledger_timestamp / config.epoch_length_secs)
accepted epoch   ∈ { epoch, epoch - 1 }        and not already closed
min_cases        = max(config.min_cases, zone.min_cases)
baseline_eff     = max(baseline[zone][symptom], config.baseline_floor)
required         = ceil(baseline_eff × config.multiplier_bps / 10000)

alert fires when  count >= min_cases            // absolute guard rail
              and count >= required             // relative to the learned norm
              and epoch >= last_alert_epoch + config.cooldown_epochs
```

Alerts are published as an `alert` event and stored in `Alert(id)` with
`cases`, `baseline`, `severity_bps` and `triggered_at`, and stay open until the
health centre calls `resolve_alert(id)`. `cooldown_epochs` stops a sustained
outbreak from generating one alert per ledger.

**Learning the baseline (at `close_epoch`).** Let `prev` be the stored baseline
and `count` the finalised count for that epoch:

```
if no baseline yet:  baseline = baseline_floor   if the epoch had alerted
                                max(count, baseline_floor)  otherwise
else:                baseline = baseline_floor   if the epoch had alerted
                                ewma(prev, count, alpha)     otherwise
where ewma(p, c, a) = (p × (10000 − a) + c × a) / 10000   // integer
```

The "alerted epochs never become the norm" rule matters: without it, the first
outbreak would permanently raise its own cell's bar. The tests pin both halves
of this behaviour — a stable signal stops alerting once learned
(`baselines_adapt_so_a_stable_signal_stops_alerting`), and a genuine spike still
fires (`a_genuine_spike_still_alerts_after_learning`).

## 4. Threat model and honest limitations

| Scenario | Behaviour |
| --- | --- |
| Student tries to report twice in one epoch | `DuplicateReport`; the nullifier is consumed |
| Outsider forges a credential or a path | `InvalidProof` |
| Reporter backdates an epoch or floods a closed epoch | `EpochOutOfWindow`, `EpochClosed` |
| Reporter invents coordinates outside the geofence | `CellNotInZone` |
| Reporter inflates one cell with one credential | blocked: one report per credential per epoch |
| Health centre wants to read a single student's report | impossible: no identity, no precise location, no sub-`k` counts |
| Health centre is malicious and unregisters a zone | detections stop for that zone, but past data stays intact and auditable |
| Outsider wants to spam the contract | they need a credential; the enrolled credential set bounds the report volume |

**Trust assumptions and known weaknesses, stated plainly.**

- **Credential custody.** Anonymity at the leaf level depends on the issuer
  *not* retaining the leaf → student mapping. The intended custody rule is
  *root-only*: the issuer stores the Merkle root and hands each leaf to its
  student, then forgets it. An issuer that keeps the mapping (or logs it at
  issuance) can link a leaf on chain to a student. The contract cannot enforce
  this; it can only avoid ever asking for the mapping.
- **Transaction-graph linkage.** The contract writes no address, but the
  transaction source on a public network is still a leak. Reports are expected
  to be relayed (fee-bump / relayer service), ideally batched, so the reporter's
  account never appears as a source.
- **Small-cell inference.** k-anonymity hides the exact count, not the existence
  of a signal: a suppressed cell still tells an observer "between 1 and k−1
  reports". `k_anon` should be set from the real population of each zone.
- **Poisoning.** Credentials are issued by the health centre, so a compromised
  issuer can mint many — the attack is bounded by enrollment, not by the
  contract. Publishing the enrollment count with each root rotation is the
  recommended mitigation; the tree root itself is public and auditable.
- **No ZK membership proof (yet).** Eligibility uses a plain Merkle path, which
  is verified cheaply but does reveal *a* leaf. The upgrade path is a Groth16/PLONK
  verifier contract proving "I hold a leaf in the current root" without revealing
  which leaf, which removes the issuer-custody assumption entirely. The report
  format (`leaf`, `index`, `path`, `nullifier`, `commitment`) is deliberately
  shaped so that swapping the proof verifier is a contained change.
- **Alerts are public.** That is the point of the protocol, but it means an
  alert reveals that a zone has at least `min_cases` cases. `min_cases` is the
  disclosure dial.
- **Rewards are out of scope.** Because reports are unlinkable, there is no
  on-chain way to reward a reporter. That belongs to an opt-in, student-initiated
  disclosure flow, not to this contract.

## 5. Public interface

Lifecycle and configuration (admin = campus health centre, `require_auth`):

| Function | Purpose |
| --- | --- |
| `initialize(admin, config)` | one-time setup |
| `set_config(config)`, `set_admin(new_admin)` | tune parameters, hand over the role |
| `rotate_credentials(root)` | install a new anonymous credential set |
| `register_zone(zone_id, label, min_cases, cells)` | create a geofenced zone |
| `add_zone_cells(zone_id, cells)`, `set_zone_active(zone_id, active)` | maintain the geofence / take a zone out of service |
| `close_epoch(epoch)` | learn baselines, publish the k-anon summary, **purge** raw telemetry |
| `purge_summary(epoch)`, `resolve_alert(id)` | retention policy, alert closure |

Reporting (no auth, no identity):

| Function | Purpose |
| --- | --- |
| `submit_report(report) -> Reading` | file one shielded report, returns a k-anon-safe reading |

Reads and audit:

| Function | Purpose |
| --- | --- |
| `cell_reading(zone, symptom, epoch) -> Reading` | `Empty` / `Suppressed` / `Visible(n)` |
| `summary(epoch) -> Vec<SummaryCell>` | every cell above `k_anon`, nothing below |
| `alerts(from_id, limit)`, `alert(id)`, `active_alerts()`, `alerting(zone, symptom)` | alert feed |
| `baseline_of(zone, symptom)`, `config()`, `admin()`, `epoch_now()`, `credential_root()`, `zone(id)`, `zones()`, `is_cell_in_zone(zone, cell)` | state inspection |
| `derive_leaf`, `derive_nullifier`, `derive_commitment` | client-side derivation, no reimplementation needed |
| `verify_credential(leaf, index, path)`, `verify_disclosure(report)` | pre-flight check and voluntary disclosure |

Events (typed, and part of the contract spec): `init`, `config`, `admin`,
`cred`, `zone`, `zonecell`, `zoneact`, `report`, `alert`, `resolved`, `epoch`,
`purged`.

## 6. Parameters

| Field | Meaning | Suggested starting point |
| --- | --- | --- |
| `k_anon` | suppression threshold on every read, `>= 3` | 5–10 depending on zone population |
| `min_cases` | absolute floor for an alert (per zone override available) | 5–10 for a dorm of a few hundred |
| `multiplier_bps` | alert multiple of the learned baseline, `10000` = 1x | `30000` (3x) |
| `baseline_floor` | baseline floor in cases, prevents 1-case hair triggers | 2–3 |
| `cooldown_epochs` | minimum epochs between alerts on one cell | 2 |
| `baseline_alpha_bps` | weight of the newest epoch in the moving average | `2500` (25%) |
| `epoch_length_secs` | reporting epoch length (daily = `86400`) | `86400` |
| `max_proof_depth` | Merkle depth cap, `<= 32`, bounds verification cost | 16 |
| `max_cells_per_epoch` | distinct cells per epoch, bounds close-time work | 256 |

DoS bounds are fixed in code: `MAX_ZONES = 128`, `MAX_ACTIVE_ALERTS = 64`, alert
pages are capped at 64 records, and persistent entries have their TTL extended to
roughly 30 days (threshold ~1 day) on every write.

## 7. Repository layout

```
contracts/mindshield/
  src/lib.rs      contract entry points, storage helpers, alert evaluation
  src/types.rs    ABI types, storage keys, error codes
  src/crypto.rs   domain-separated hashing and Merkle verification
  src/events.rs   typed contract events (included in the contract spec)
  src/test.rs     29 behavioural tests
tools/
  mindshield_client.py   issuer + student-device reference client (stdlib only)
deployments/
  testnet.json    machine-readable record of the live testnet deployment
Makefile                test / lint / fmt / wasm
```

## 8. Deployed on Stellar testnet

| | |
| --- | --- |
| Network | Stellar testnet |
| Contract | `CAULIGUW774GXMSF4SPJJDP5FLTTV42NEGT64ORMOXWDZZA5H35IVNAI` |
| Wasm hash | `d9c13cc2dfcb7b83e44e99549d6a46ca5817e88178ce477915bdf72d69cd7ce5` |
| Admin (health centre) | `GAVDTMS3D375D4VFP43M3O7VNC3X24ZMLE6RR434DJCGWYBWEYRVUHDL` |
| Explorer | [stellar.expert][c1] · [lab.stellar.org][c2] |

The same record is kept machine-readable in `deployments/testnet.json` (contract
id, wasm sha256, admin, transaction hashes, the initialised parameters and the
demo state left on chain), so a redeploy or an audit can be diffed against it.
The wasm upload, deployment and initialisation transactions are public on the
explorer; the initialisation call is [5c437da7][t1], `register_zone` is
[3d15059d][t2] and the first credential rotation is [cfa34494][t3].

**What was verified on the live network** (epoch length one day, so the current
epoch was 20735):

1. `initialize` with `k_anon = 5`, `min_cases = 5`, `multiplier_bps = 30000`,
   `baseline_floor = 2`; `config` reads back bit-for-bit.
2. `register_zone` for `dorm_north` with coarse cells `[10, 11]`, and
   `rotate_credentials` with the Merkle root produced by
   `tools/mindshield_client.py enroll --students 8`. The contract's
   `verify_credential` returned **true** for that client's leaf and path and
   **false** for an outsider leaf — so the contract and the independent Python
   implementation agree on every derivation and on the tree layout.
3. Six reports filed from six distinct credentials, all relayed from a single
   account that the contract never records. The returned readings show the
   k-anonymity mask lifting exactly at `k`: `Suppressed`, `Suppressed`,
   `Suppressed`, `Suppressed`, `Visible(5)`, `Visible(6)`.
4. On the sixth case the contract raised
   [OutbreakAlert](https://stellar.expert/explorer/testnet/contract/CAULIGUW774GXMSF4SPJJDP5FLTTV42NEGT64ORMOXWDZZA5H35IVNAI)
   `id 1, zone 1, symptom 1, epoch 20735, cases 6, baseline 2, severity_bps 30000`
   without anyone asking it to. `alerting(1, 1)` is `true` and `active_alerts`
   returns it.
5. Negative paths behave as specified on chain: re-filing the same credential in
   the same epoch fails with `Error(Contract, #9)` (DuplicateReport), and a report
   for `geocell 999` fails with `Error(Contract, #5)` (CellNotInZone).
6. Five reports for the *previous* epoch (20734, the relay-latency grace window)
   were accepted; `close_epoch(20734)` published the k-anonymised summary
   `[{cases: 5, symptom: 1, zone_id: 1}]`, learned `baseline_of(1, 1) == 5`, and
   purged the raw counters and nullifier markers. A report for that now-closed
   epoch is then rejected with `Error(Contract, #13)` (EpochClosed).
7. Every event above was decoded by stellar-cli from the embedded contract spec
   (`ReportSubmitted`, `OutbreakAlert`, `EpochClosed`, …), and each `report`
   event carries only an opaque commitment — no leaf, no address.

Not exercised live: the ZK-membership upgrade path (not implemented), mainnet,
and the multi-zone / per-zone `min_cases` variants, which the unit tests cover.

## 9. Build and test

Requires Rust 1.84+. Soroban SDK 27 needs the `wasm32v1-none` target (the old
`wasm32-unknown-unknown` target is rejected by the SDK on Rust 1.82+).

```bash
rustup target add wasm32v1-none

cargo test                                   # 29 tests
cargo clippy --all-targets -- -D warnings    # clean
cargo fmt --all -- --check
cargo build --target wasm32v1-none --release # target/wasm32v1-none/release/mindshield.wasm
```

or `make test`, `make lint`, `make wasm`.

### Operating it with stellar-cli

`tools/mindshield_client.py` is the off-chain half: the issuer runs `enroll` to
build a credential set, and each student device runs `report` to build one
shielded report. It is stdlib-only Python and reproduces the contract's
hash derivations, so it needs no SDK.

```bash
# issuer: build a credential set and get the root to publish
python3 tools/mindshield_client.py enroll --students 8 --out roster.json

stellar contract deploy --wasm target/wasm32v1-none/release/mindshield.wasm \
  --source <issuer-key> --network testnet

stellar contract invoke --id <CONTRACT_ID> --source-account <issuer-key> --network testnet -- \
  initialize --admin <HEALTH_CENTRE_ADDRESS> \
  --config '{"k_anon":5,"min_cases":5,"multiplier_bps":30000,"baseline_floor":2,"cooldown_epochs":2,"baseline_alpha_bps":2500,"epoch_length_secs":86400,"max_proof_depth":16,"max_cells_per_epoch":256}'

stellar contract invoke --id <CONTRACT_ID> --source-account <issuer-key> --network testnet -- \
  register_zone --zone_id 1 --label dorm_north --min_cases 0 --cells '[10, 11]'
stellar contract invoke --id <CONTRACT_ID> --source-account <issuer-key> --network testnet -- \
  rotate_credentials --root <ROOT_FROM_ENROLL>

# student device (or relayer): build one report, then file it from a relayer
# account so the reporter's own account never appears as a transaction source
python3 tools/mindshield_client.py report --roster roster.json --student 0 \
  --zone 1 --geocell 10 --symptom fever --epoch <EPOCH> --quiet > report.json
stellar contract invoke --id <CONTRACT_ID> --source-account <relayer-key> --network testnet -- \
  submit_report --report-file-path report.json
```

Two stellar-cli details worth knowing: `--source-account` is required even for
read-only calls, and `Vec`/struct arguments must come from a file
(`--path-file-path`, `--report-file-path`) rather than an inline JSON string.
`BytesN` arguments are hex. `roster.json` is the only thing that links a leaf to
a student — deliver it privately and delete it.

## 10. Test coverage

`cargo test` runs 29 tests. Highlights, grouped by the invariant they defend:

- **k-anonymity**: `counts_below_k_are_never_returned`,
  `cells_are_scoped_by_zone_symptom_and_epoch`,
  `close_epoch_purges_raw_telemetry_and_keeps_only_k_anonymous_cells`,
  `summary_retention_can_be_purged`.
- **Credential shielding**: `forged_credentials_are_rejected`,
  `proof_depth_is_bounded`, `nullifier_and_commitment_must_bind_the_credential`,
  `one_report_per_credential_per_epoch`,
  `reporting_requires_no_authorisation_and_leaks_no_credential`,
  `undisclosed_credentials_are_not_traceable_through_events`.
- **Geofencing**: `geofence_rejects_unknown_zones_and_unlisted_cells`,
  `only_coarse_symptom_classes_are_accepted`,
  `inactive_zone_refuses_new_reports_but_keeps_its_history`.
- **Epoch lifecycle**: `epoch_window_rejects_backdating_and_closed_epochs`,
  `close_epoch_requires_a_past_epoch`, `close_epoch_learns_baselines`,
  `per_epoch_cell_cap_is_enforced_without_burning_the_credential`.
- **Outbreak detection**: `alert_fires_automatically_when_the_multiple_is_crossed`,
  `cooldown_prevents_alert_spam`, `per_zone_min_cases_override_is_honoured`,
  `baselines_adapt_so_a_stable_signal_stops_alerting`,
  `a_genuine_spike_still_alerts_after_learning`, `alerts_can_be_resolved`.
- **Crypto and audit**: `derivations_match_an_independent_implementation`
  (every hash recomputed independently in the test),
  `reference_client_matches_the_contract` (pins the Merkle root produced by
  `tools/mindshield_client.py` to the Rust implementation),
  `verify_disclosure_round_trip`, plus admin authorisation checks.

## 11. Roadmap

1. ZK membership verifier so eligibility no longer depends on the issuer
   forgetting the leaf mapping.
2. Relayer + batching service so report transactions are unlinkable at the
   transaction-graph level as well.
3. Per-student opt-in disclosure flow (counselling hand-off, hardship grants)
   built on `verify_disclosure`, with the reward path deliberately off-chain.
4. Zone-level population metadata, so `k_anon` and `min_cases` can be derived
   from real occupancy instead of being hand-tuned.

[c1]: https://stellar.expert/explorer/testnet/contract/CAULIGUW774GXMSF4SPJJDP5FLTTV42NEGT64ORMOXWDZZA5H35IVNAI
[c2]: https://lab.stellar.org/r/testnet/contract/CAULIGUW774GXMSF4SPJJDP5FLTTV42NEGT64ORMOXWDZZA5H35IVNAI
[t1]: https://stellar.expert/explorer/testnet/tx/5c437da78fb744dc154013d11544ff5a499c1199295fd954d2727f55f64a7f4e
[t2]: https://stellar.expert/explorer/testnet/tx/3d15059db588df06c0363e789928629e6749e3f7b1ea5661363df6465554a9d9
[t3]: https://stellar.expert/explorer/testnet/tx/cfa34494c53d758aebc917d2eef83747236acd4d054bf4cbaae4b05060c1850c

## License

MIT
