//! Typed contract events.
//!
//! Every event carries only public, aggregate information. The one field that
//! could be sensitive, the report commitment, is an opaque hash that reveals
//! nothing unless the reporting student chooses to disclose the opening.
//!
//! Using `#[contractevent]` puts these definitions into the contract spec, so
//! generated clients and indexers can consume them without hand-parsing topics.

use crate::types::{Config, SummaryCell};
use soroban_sdk::{contractevent, Address, BytesN, Vec};

/// Protocol deployed. `k_anon` and `min_cases` are echoed so an indexer can
/// record the privacy parameters in force from the first ledger.
#[contractevent(topics = ["init"])]
#[derive(Clone, Debug, PartialEq)]
pub struct Initialized {
    #[topic]
    pub admin: Address,
    pub k_anon: u32,
    pub min_cases: u32,
}

/// Protocol parameters changed.
#[contractevent(topics = ["config"])]
#[derive(Clone, Debug, PartialEq)]
pub struct ConfigUpdated {
    pub config: Config,
}

/// Administrator handover.
#[contractevent(topics = ["admin"])]
#[derive(Clone, Debug, PartialEq)]
pub struct AdminChanged {
    #[topic]
    pub admin: Address,
    pub previous: Address,
}

/// The anonymous credential set was rotated. Only the root is published: the
/// issuer keeps no leaf-to-student mapping on chain.
#[contractevent(topics = ["cred"])]
#[derive(Clone, Debug, PartialEq)]
pub struct CredentialsRotated {
    pub root: BytesN<32>,
}

/// A geofenced reporting zone was registered.
#[contractevent(topics = ["zone"])]
#[derive(Clone, Debug, PartialEq)]
pub struct ZoneRegistered {
    #[topic]
    pub zone_id: u32,
    pub label: soroban_sdk::Symbol,
    pub min_cases: u32,
}

/// Coarse geo-cells were added to a zone's geofence.
#[contractevent(topics = ["zonecell"])]
#[derive(Clone, Debug, PartialEq)]
pub struct ZoneCellsAdded {
    #[topic]
    pub zone_id: u32,
    pub cells: Vec<u64>,
}

/// A zone was taken out of service, or brought back.
#[contractevent(topics = ["zoneact"])]
#[derive(Clone, Debug, PartialEq)]
pub struct ZoneStatusChanged {
    #[topic]
    pub zone_id: u32,
    pub active: bool,
}

/// A shielded report was accepted. The topics are the aggregate coordinates
/// only; the payload is the opaque commitment, never the credential leaf.
#[contractevent(topics = ["report"])]
#[derive(Clone, Debug, PartialEq)]
pub struct ReportSubmitted {
    #[topic]
    pub epoch: u32,
    #[topic]
    pub zone_id: u32,
    #[topic]
    pub symptom: u32,
    pub commitment: BytesN<32>,
}

/// An outbreak alert fired automatically because a cell crossed its threshold
/// multiple of the learned baseline. This is the signal the campus health
/// centre reacts to, typically days before lab confirmation.
#[contractevent(topics = ["alert"])]
#[derive(Clone, Debug, PartialEq)]
pub struct OutbreakAlert {
    #[topic]
    pub id: u64,
    #[topic]
    pub zone_id: u32,
    #[topic]
    pub symptom: u32,
    pub epoch: u32,
    pub cases: u32,
    pub baseline: u32,
    pub severity_bps: u32,
    pub triggered_at: u64,
}

/// An alert was closed out by the health centre.
#[contractevent(topics = ["resolved"])]
#[derive(Clone, Debug, PartialEq)]
pub struct AlertResolved {
    #[topic]
    pub id: u64,
    pub resolved_at: u64,
}

/// An epoch was finalised. Only k-anonymised cells appear in the summary, and
/// the raw telemetry for the epoch has already been deleted when this fires.
#[contractevent(topics = ["epoch"])]
#[derive(Clone, Debug, PartialEq)]
pub struct EpochClosed {
    #[topic]
    pub epoch: u32,
    pub summary: Vec<SummaryCell>,
}

/// A retained epoch summary was purged under the retention policy.
#[contractevent(topics = ["purged"])]
#[derive(Clone, Debug, PartialEq)]
pub struct EpochSummaryPurged {
    #[topic]
    pub epoch: u32,
    pub purged_at: u64,
}
