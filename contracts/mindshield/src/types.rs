//! Public data types, storage keys and error codes for the MindShield protocol.
//!
//! Everything in this module is part of the contract ABI (it is `#[contracttype]`),
//! so the shapes here are what wallets, the health-centre console and the
//! university's anonymous credential issuer compile against.

use soroban_sdk::{contracterror, contracttype, BytesN, Symbol, Vec};

/// Symptom classes are coarse, pre-agreed categories. Free text is deliberately
/// impossible: a category is the minimum amount of information needed to detect
/// an outbreak signal, and it keeps the on-chain key space bounded.
///
/// The contract accepts any code in `1..=MAX_SYMPTOM_CLASS`; these constants are
/// the convention the campus health centre is expected to publish.
pub const SYMPTOM_FEVER: u32 = 1;
pub const SYMPTOM_RESPIRATORY: u32 = 2;
pub const SYMPTOM_GASTROINTESTINAL: u32 = 3;
pub const SYMPTOM_HEADACHE: u32 = 4;
pub const SYMPTOM_RASH: u32 = 5;
pub const SYMPTOM_FATIGUE: u32 = 6;

/// Highest symptom code the contract will accept.
pub const MAX_SYMPTOM_CLASS: u32 = 32;

/// Storage keys. Soroban keys must be deterministic, and we avoid storing any
/// key that could identify a reporter.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Instance: contract administrator (the campus health centre).
    Admin,
    /// Instance: protocol parameters.
    Config,
    /// Instance: Merkle root of the current anonymous credential set.
    CredentialRoot,
    /// Instance: monotonically increasing alert id counter.
    AlertSeq,
    /// Persistent: ids of alerts that have not been resolved, capped.
    ActiveAlerts,
    /// Persistent: registered zone ids.
    ZoneIds,
    /// Persistent: zone definition.
    Zone(u32),
    /// Persistent: coarse geo-cell belongs to a zone (geofence allow-list).
    ZoneCell(u32, u64),
    /// Persistent: consumption marker for a one-time report nullifier.
    /// Keyed by epoch so the marker set can be purged when the epoch closes.
    Nullifier(u32, BytesN<32>),
    /// Persistent: nullifiers consumed during an epoch, for purge-on-close.
    EpochNullifiers(u32),
    /// Persistent: live per-epoch symptom counter for a (zone, symptom) cell.
    /// Deleted by `close_epoch`: raw telemetry is transient by design.
    Cell(u32, u32, u32),
    /// Persistent: cells touched during an epoch, so closing is enumerable.
    EpochCells(u32),
    /// Persistent: k-anonymised aggregate retained after an epoch closes.
    EpochSummary(u32),
    /// Persistent: epoch has been finalised, further reports are rejected.
    EpochClosed(u32),
    /// Persistent: learned per-epoch baseline for a (zone, symptom) cell.
    Baseline(u32, u32),
    /// Persistent: epoch of the most recent alert for a (zone, symptom) cell.
    LastAlertEpoch(u32, u32),
    /// Persistent: alert record.
    Alert(u64),
}

/// Protocol parameters, all tunable by the health centre.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// k-anonymity: no read path will ever return a count below this value.
    /// Must be >= 3 to be meaningful.
    pub k_anon: u32,
    /// Absolute floor of cases before an outbreak alert can fire, per zone.
    pub min_cases: u32,
    /// Alert threshold as a multiple of the learned baseline, in basis points.
    /// 10000 = fire at 1x baseline, 30000 = fire at 3x baseline.
    pub multiplier_bps: u32,
    /// Baseline floor in cases, so a quiet cell cannot fire on a 1-case blip.
    pub baseline_floor: u32,
    /// Minimum number of epochs between two alerts for the same cell.
    pub cooldown_epochs: u32,
    /// Weight of the newest epoch in the exponential moving average baseline,
    /// in basis points (2500 = the new epoch is 25% of the baseline).
    pub baseline_alpha_bps: u32,
    /// Reporting epoch length in seconds, for example 86400 for a daily epoch.
    pub epoch_length_secs: u64,
    /// Maximum Merkle proof depth accepted, bounds verification cost.
    pub max_proof_depth: u32,
    /// Maximum distinct cells that may be written in a single epoch, bounds the
    /// per-epoch enumeration cost at close time.
    pub max_cells_per_epoch: u32,
}

/// A geofenced reporting zone: a dorm cluster, dining hall, faculty building,
/// or any other coarse campus location.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zone {
    pub id: u32,
    pub label: Symbol,
    pub active: bool,
    /// Per-zone override of `Config::min_cases` when greater than zero.
    pub min_cases: u32,
    pub created_epoch: u32,
}

/// A shielded symptom report.
///
/// Note what is *absent*: no address, no student id, no precise coordinates,
/// no free text, no signature by the reporter. The report is bound to an
/// anonymous credential by a Merkle inclusion proof, and to a one-time
/// nullifier so a credential cannot be counted twice in the same epoch.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    /// Destination zone.
    pub zone_id: u32,
    /// Coarse geo-cell inside the zone. Must be on the zone's allow-list.
    pub geocell: u64,
    /// Coarse symptom class, see `SYMPTOM_*`.
    pub symptom: u32,
    /// Reporting epoch. Must be the current or previous epoch.
    pub epoch: u32,
    /// Anonymous credential leaf, a blinded commitment to the student's secret.
    pub leaf: BytesN<32>,
    /// Leaf position in the credential Merkle tree (bits choose left/right).
    pub index: u32,
    /// Merkle inclusion path for `leaf`.
    pub path: Vec<BytesN<32>>,
    /// One-time tag, `derive_nullifier(leaf, epoch)`. Consumed on acceptance.
    pub nullifier: BytesN<32>,
    /// `derive_commitment(...)` binding every field above to the credential,
    /// which enables voluntary selective disclosure later.
    pub commitment: BytesN<32>,
}

/// A (zone, symptom) pair, the unit of aggregation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellKey {
    pub zone_id: u32,
    pub symptom: u32,
}

/// Result of reading an aggregate. There is no way to observe a sub-`k` count:
/// either it is visible, or it is suppressed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reading {
    /// No reports recorded for this cell and epoch.
    Empty,
    /// Reports exist but fewer than `k_anon`, so the count is withheld.
    Suppressed,
    /// At or above `k_anon`, safe to publish.
    Visible(u32),
}

/// A k-anonymised aggregate cell, the only shape in which raw telemetry leaves
/// the contract.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SummaryCell {
    pub zone_id: u32,
    pub symptom: u32,
    pub cases: u32,
}

/// An automatically triggered outbreak alert. Alerts are public and contain
/// only aggregate information: never a reporter, never a leaf.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Alert {
    pub id: u64,
    pub zone_id: u32,
    pub symptom: u32,
    /// Epoch during which the threshold was crossed.
    pub epoch: u32,
    /// Cases observed when the alert fired.
    pub cases: u32,
    /// Learned baseline the cell was compared against, in cases per epoch.
    pub baseline: u32,
    /// Observed cases as a percentage of the effective baseline, in basis
    /// points. 10000 means exactly at baseline, 35000 means 3.5x.
    pub severity_bps: u32,
    pub triggered_at: u64,
    pub resolved: bool,
}

/// What `verify_disclosure` proves about a report handed back to the contract.
/// Used when a student voluntarily discloses "I filed this report" to a
/// counsellor, or when the health centre audits a disputed alert.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disclosure {
    /// The credential was valid in the credential set that was live at the
    /// time of the report.
    pub credential_valid: bool,
    /// The nullifier is the one derived from the disclosed leaf and epoch.
    pub nullifier_bound: bool,
    /// The commitment binds every reported field to that leaf.
    pub commitment_bound: bool,
    /// The nullifier was actually accepted by the protocol.
    pub nullifier_used: bool,
}

/// Contract errors.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    UnknownZone = 3,
    ZoneInactive = 4,
    CellNotInZone = 5,
    InvalidSymptom = 6,
    InvalidProof = 7,
    ProofTooDeep = 8,
    DuplicateReport = 9,
    BadNullifier = 10,
    BadCommitment = 11,
    EpochOutOfWindow = 12,
    EpochClosed = 13,
    EpochTooRecent = 14,
    AlreadyClosed = 15,
    InvalidConfig = 16,
    MaxZonesReached = 17,
    CellLimitReached = 18,
    UnknownAlert = 19,
    InvalidZone = 20,
    EmptyCellList = 21,
}
