#![cfg_attr(not(test), no_std)]
//! # MindShield — privacy-preserving campus epidemiology
//!
//! MindShield aggregates *shielded*, geofenced symptom reports on Soroban and
//! raises campus outbreak alerts automatically, without ever recording who
//! reported what.
//!
//! ## What the chain stores
//!
//! Accepted reports leave behind only four things:
//!
//! 1. a one-time **nullifier** marker (`H(0x05 || leaf || epoch)`) that prevents
//!    the same credential being counted twice in an epoch;
//! 2. a **counter** for a coarse `(epoch, zone, symptom)` cell;
//! 3. an opaque **commitment** in the event log, for opt-in disclosure later;
//! 4. **alerts** and, after an epoch closes, k-anonymised **summaries**.
//!
//! No address, student identifier, precise coordinate or free-text field is
//! written to storage. Reports are expected to be relayed by a third party so
//! that the transaction source does not leak the reporter's account either.
//!
//! ## Privacy invariants enforced by the contract
//!
//! * **k-anonymity on every read path.** `cell_reading` and `summary` never
//!   return a count below `Config::k_anon`; below that they return
//!   `Reading::Suppressed`.
//! * **One credential, one report per epoch.** Enforced by the nullifier, which
//!   is derived from the credential and the epoch, so double-counting is
//!   impossible while repeat reporting across epochs still works.
//! * **Eligibility without identity.** A Merkle inclusion proof over anonymous
//!   credential leaves proves the reporter is an enrolled student without
//!   naming them.
//! * **Coarse geofencing.** Reports bind to a registered coarse geo-cell; the
//!   contract rejects cells that are not on the zone allow-list, so precise
//!   location cannot be smuggled on-chain.
//! * **Transient raw telemetry.** `close_epoch` folds each cell into a learned
//!   baseline, then *deletes* the raw counters and the epoch's nullifier
//!   markers, retaining only aggregates that passed the k threshold.
//!
//! See the repository README for the full privacy and threat model, including
//! the credential-custody trust assumption and the ZK membership proof upgrade
//! path.

mod crypto;
pub mod events;
mod types;

#[cfg(test)]
mod test;

use crate::crypto::derive_commitment;
use crate::events::{
    AdminChanged, AlertResolved, ConfigUpdated, CredentialsRotated, EpochClosed,
    EpochSummaryPurged, Initialized, OutbreakAlert, ReportSubmitted, ZoneCellsAdded,
    ZoneRegistered, ZoneStatusChanged,
};
pub use crate::types::*;
use soroban_sdk::{
    contract, contractimpl, Address, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec,
};

/// Ledger count below which persistent/instance entries are extended.
/// At roughly 5 seconds per ledger this is about one day.
const TTL_THRESHOLD: u32 = 17_280;
/// Target TTL for live entries, about 30 days.
const TTL_EXTEND: u32 = 518_400;
/// Upper bound on registered zones, keeps `zones()` and enumeration bounded.
const MAX_ZONES: u32 = 128;
/// Upper bound on the unresolved-alert ring buffer.
const MAX_ACTIVE_ALERTS: u32 = 64;
/// Upper bound on one page of `alerts()`.
const MAX_ALERT_PAGE: u32 = 64;

#[contract]
pub struct MindShield;

#[contractimpl]
impl MindShield {
    // ---------------------------------------------------------------- lifecycle

    /// One-time initialisation. `admin` is the campus health centre.
    pub fn initialize(env: Env, admin: Address, config: Config) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        validate_config(&config)?;

        put_instance(&env, &DataKey::Admin, &admin);
        put_instance(&env, &DataKey::Config, &config);
        put_instance(
            &env,
            &DataKey::CredentialRoot,
            &BytesN::from_array(&env, &[0u8; 32]),
        );
        put_instance(&env, &DataKey::AlertSeq, &0u64);
        put_persistent(&env, &DataKey::ZoneIds, &Vec::<u32>::new(&env));
        put_persistent(&env, &DataKey::ActiveAlerts, &Vec::<u64>::new(&env));
        bump_instance(&env);

        Initialized {
            admin,
            k_anon: config.k_anon,
            min_cases: config.min_cases,
        }
        .publish(&env);
        Ok(())
    }

    /// Update the protocol parameters, for example to tighten `k_anon`.
    pub fn set_config(env: Env, config: Config) -> Result<(), Error> {
        require_admin(&env)?;
        validate_config(&config)?;
        bump_instance(&env);
        put_instance(&env, &DataKey::Config, &config);
        ConfigUpdated {
            config: config.clone(),
        }
        .publish(&env);
        Ok(())
    }

    /// Hand the administrator role to a new address.
    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let previous = require_admin(&env)?;
        bump_instance(&env);
        put_instance(&env, &DataKey::Admin, &new_admin);
        AdminChanged {
            admin: new_admin,
            previous,
        }
        .publish(&env);
        Ok(())
    }

    pub fn admin(env: Env) -> Result<Address, Error> {
        read_admin(&env)
    }

    pub fn config(env: Env) -> Result<Config, Error> {
        read_config(&env)
    }

    /// Current reporting epoch, derived from ledger time rather than chosen by
    /// any caller.
    pub fn epoch_now(env: Env) -> Result<u32, Error> {
        current_epoch(&env)
    }

    pub fn credential_root(env: Env) -> BytesN<32> {
        read_root(&env)
    }

    /// Install a new anonymous credential set. The root is the only thing the
    /// issuer needs to keep; see the credential custody rule in the README.
    pub fn rotate_credentials(env: Env, root: BytesN<32>) -> Result<(), Error> {
        require_admin(&env)?;
        if root == BytesN::from_array(&env, &[0u8; 32]) {
            return Err(Error::InvalidProof);
        }
        bump_instance(&env);
        put_instance(&env, &DataKey::CredentialRoot, &root);
        CredentialsRotated { root }.publish(&env);
        Ok(())
    }

    // ------------------------------------------------------------ zones/geofence

    /// Register a geofenced reporting zone with its coarse geo-cell allow-list.
    pub fn register_zone(
        env: Env,
        zone_id: u32,
        label: Symbol,
        min_cases: u32,
        cells: Vec<u64>,
    ) -> Result<(), Error> {
        require_admin(&env)?;
        bump_instance(&env);
        if zone_id == 0 || cells.is_empty() {
            return Err(Error::InvalidZone);
        }
        if env.storage().persistent().has(&DataKey::Zone(zone_id)) {
            return Err(Error::InvalidZone);
        }

        let mut ids: Vec<u32> = read_persistent_or(&env, &DataKey::ZoneIds, Vec::new(&env));
        if ids.len() >= MAX_ZONES {
            return Err(Error::MaxZonesReached);
        }
        ids.push_back(zone_id);
        put_persistent(&env, &DataKey::ZoneIds, &ids);

        for cell in cells.iter() {
            if cell == 0 {
                return Err(Error::InvalidZone);
            }
            put_persistent(&env, &DataKey::ZoneCell(zone_id, cell), &true);
        }

        let zone = Zone {
            id: zone_id,
            label,
            active: true,
            min_cases,
            created_epoch: current_epoch(&env)?,
        };
        put_persistent(&env, &DataKey::Zone(zone_id), &zone);
        ZoneRegistered {
            zone_id,
            label: zone.label.clone(),
            min_cases: zone.min_cases,
        }
        .publish(&env);
        Ok(())
    }

    /// Extend a zone's geo-cell allow-list.
    pub fn add_zone_cells(env: Env, zone_id: u32, cells: Vec<u64>) -> Result<(), Error> {
        require_admin(&env)?;
        bump_instance(&env);
        read_zone(&env, zone_id)?;
        if cells.is_empty() {
            return Err(Error::EmptyCellList);
        }
        for cell in cells.iter() {
            if cell == 0 {
                return Err(Error::InvalidZone);
            }
            put_persistent(&env, &DataKey::ZoneCell(zone_id, cell), &true);
        }
        ZoneCellsAdded { zone_id, cells }.publish(&env);
        Ok(())
    }

    /// Take a zone out of service, or bring it back. Deactivating a zone stops
    /// new reports but keeps its history and baseline.
    pub fn set_zone_active(env: Env, zone_id: u32, active: bool) -> Result<(), Error> {
        require_admin(&env)?;
        bump_instance(&env);
        let mut zone = read_zone(&env, zone_id)?;
        zone.active = active;
        put_persistent(&env, &DataKey::Zone(zone_id), &zone);
        ZoneStatusChanged { zone_id, active }.publish(&env);
        Ok(())
    }

    pub fn zone(env: Env, zone_id: u32) -> Result<Zone, Error> {
        read_zone(&env, zone_id)
    }

    pub fn zones(env: Env) -> Vec<Zone> {
        let ids: Vec<u32> = read_persistent_or(&env, &DataKey::ZoneIds, Vec::new(&env));
        let mut out = Vec::new(&env);
        for id in ids.iter() {
            if let Some(zone) = env.storage().persistent().get(&DataKey::Zone(id)) {
                out.push_back(zone);
            }
        }
        out
    }

    /// Whether a coarse geo-cell is inside a zone's geofence.
    pub fn is_cell_in_zone(env: Env, zone_id: u32, geocell: u64) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::ZoneCell(zone_id, geocell))
    }

    // -------------------------------------------------------- shielded reporting

    /// Submit a shielded symptom report.
    ///
    /// Deliberately takes no reporter `Address` and calls `require_auth` on
    /// nobody: authorisation is replaced by an anonymous credential proof. The
    /// transaction source is a relayer and is never written to storage.
    ///
    /// Returns a k-anonymity-safe [`Reading`]; the raw count is never returned
    /// to a caller who could be the only reporter in the cell.
    pub fn submit_report(env: Env, report: Report) -> Result<Reading, Error> {
        let config = read_config(&env)?;
        bump_instance(&env);

        // 1. Geofence: the zone must exist, be live, and own this coarse cell.
        let zone = read_zone(&env, report.zone_id)?;
        if !zone.active {
            return Err(Error::ZoneInactive);
        }
        if !env
            .storage()
            .persistent()
            .has(&DataKey::ZoneCell(report.zone_id, report.geocell))
        {
            return Err(Error::CellNotInZone);
        }

        // 2. Only coarse, pre-agreed symptom classes are accepted.
        if report.symptom == 0 || report.symptom > MAX_SYMPTOM_CLASS {
            return Err(Error::InvalidSymptom);
        }

        // 3. The epoch is wall-clock derived and may not be backdated.
        let now = current_epoch(&env)?;
        if report.epoch > now || report.epoch.saturating_add(1) < now {
            return Err(Error::EpochOutOfWindow);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::EpochClosed(report.epoch))
        {
            return Err(Error::EpochClosed);
        }

        // 4. Eligibility: anonymous credential membership.
        if report.path.len() > config.max_proof_depth {
            return Err(Error::ProofTooDeep);
        }
        if !crypto::verify_merkle(
            &env,
            &report.leaf,
            report.index,
            &report.path,
            &read_root(&env),
        ) {
            return Err(Error::InvalidProof);
        }

        // 5. The nullifier must be the one this credential owns at this epoch.
        if crypto::derive_nullifier(&env, &report.leaf, report.epoch) != report.nullifier {
            return Err(Error::BadNullifier);
        }

        // 6. The commitment must bind the credential to the reported fields.
        if derive_commitment(
            &env,
            &report.leaf,
            &report.nullifier,
            report.symptom,
            report.zone_id,
            report.geocell,
            report.epoch,
        ) != report.commitment
        {
            return Err(Error::BadCommitment);
        }

        // 7. Bounded per-epoch enumeration, checked before anything is written.
        let cell_key = DataKey::Cell(report.epoch, report.zone_id, report.symptom);
        let current: u32 = env.storage().persistent().get(&cell_key).unwrap_or(0);
        let is_new_cell = current == 0;
        let mut cells: Vec<CellKey> =
            read_persistent_or(&env, &DataKey::EpochCells(report.epoch), Vec::new(&env));
        if is_new_cell {
            if cells.len() >= config.max_cells_per_epoch {
                return Err(Error::CellLimitReached);
            }
            cells.push_back(CellKey {
                zone_id: report.zone_id,
                symptom: report.symptom,
            });
        }

        // 8. One report per credential per epoch.
        let nullifier_key = DataKey::Nullifier(report.epoch, report.nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            return Err(Error::DuplicateReport);
        }

        // ---- commit ----
        let count = current.checked_add(1).ok_or(Error::CellLimitReached)?;
        put_persistent(&env, &nullifier_key, &true);
        let mut nullifiers: Vec<BytesN<32>> = read_persistent_or(
            &env,
            &DataKey::EpochNullifiers(report.epoch),
            Vec::new(&env),
        );
        nullifiers.push_back(report.nullifier.clone());
        put_persistent(&env, &DataKey::EpochNullifiers(report.epoch), &nullifiers);
        put_persistent(&env, &cell_key, &count);
        if is_new_cell {
            put_persistent(&env, &DataKey::EpochCells(report.epoch), &cells);
        }

        // Only the opaque commitment is published, never the leaf.
        ReportSubmitted {
            epoch: report.epoch,
            zone_id: report.zone_id,
            symptom: report.symptom,
            commitment: report.commitment.clone(),
        }
        .publish(&env);

        // 9. Automatic outbreak threshold evaluation.
        if let Some(alert) =
            evaluate_threshold(&env, &config, &zone, report.epoch, report.symptom, count)
        {
            publish_alert(&env, &alert);
        }

        Ok(mask(&config, count))
    }

    // -------------------------------------------------------------- read paths

    /// Read one aggregate cell. Never returns a sub-`k` count.
    pub fn cell_reading(
        env: Env,
        zone_id: u32,
        symptom: u32,
        epoch: u32,
    ) -> Result<Reading, Error> {
        let config = read_config(&env)?;
        if symptom == 0 || symptom > MAX_SYMPTOM_CLASS {
            return Err(Error::InvalidSymptom);
        }
        if env.storage().persistent().has(&DataKey::EpochClosed(epoch)) {
            let summary: Vec<SummaryCell> =
                read_persistent_or(&env, &DataKey::EpochSummary(epoch), Vec::new(&env));
            for cell in summary.iter() {
                if cell.zone_id == zone_id && cell.symptom == symptom {
                    return Ok(Reading::Visible(cell.cases));
                }
            }
            return Ok(Reading::Empty);
        }
        let count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Cell(epoch, zone_id, symptom))
            .unwrap_or(0);
        Ok(mask(&config, count))
    }

    /// All k-anonymised cells for an epoch. Sub-`k` cells are omitted entirely.
    pub fn summary(env: Env, epoch: u32) -> Result<Vec<SummaryCell>, Error> {
        let config = read_config(&env)?;
        if env.storage().persistent().has(&DataKey::EpochClosed(epoch)) {
            return Ok(read_persistent_or(
                &env,
                &DataKey::EpochSummary(epoch),
                Vec::new(&env),
            ));
        }
        let cells: Vec<CellKey> =
            read_persistent_or(&env, &DataKey::EpochCells(epoch), Vec::new(&env));
        let mut out = Vec::new(&env);
        for cell in cells.iter() {
            let count: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::Cell(epoch, cell.zone_id, cell.symptom))
                .unwrap_or(0);
            if count >= config.k_anon {
                out.push_back(SummaryCell {
                    zone_id: cell.zone_id,
                    symptom: cell.symptom,
                    cases: count,
                });
            }
        }
        Ok(out)
    }

    /// Whether an unreplied alert is currently open for a cell.
    pub fn alerting(env: Env, zone_id: u32, symptom: u32) -> bool {
        let active: Vec<u64> = read_persistent_or(&env, &DataKey::ActiveAlerts, Vec::new(&env));
        for id in active.iter() {
            if let Some(alert) = env
                .storage()
                .persistent()
                .get::<DataKey, Alert>(&DataKey::Alert(id))
            {
                if alert.zone_id == zone_id && alert.symptom == symptom && !alert.resolved {
                    return true;
                }
            }
        }
        false
    }

    /// Learned baseline in cases per epoch for a cell, and the threshold it
    /// implies. Admin-facing tuning aid; contains no personal data.
    pub fn baseline_of(env: Env, zone_id: u32, symptom: u32) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Baseline(zone_id, symptom))
            .unwrap_or(0)
    }

    // ------------------------------------------------------------------ alerts

    pub fn alert(env: Env, id: u64) -> Result<Alert, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Alert(id))
            .ok_or(Error::UnknownAlert)
    }

    /// Page through alerts by id. Alerts are public: they contain only
    /// aggregates, never a reporter.
    pub fn alerts(env: Env, from_id: u64, limit: u32) -> Vec<Alert> {
        let seq: u64 = read_instance_or(&env, &DataKey::AlertSeq, 0u64);
        let page = if limit > MAX_ALERT_PAGE {
            MAX_ALERT_PAGE
        } else {
            limit
        };
        let mut out = Vec::new(&env);
        let mut id = if from_id < 1 { 1 } else { from_id };
        while id <= seq && out.len() < page {
            if let Some(alert) = env
                .storage()
                .persistent()
                .get::<DataKey, Alert>(&DataKey::Alert(id))
            {
                out.push_back(alert);
            }
            id += 1;
        }
        out
    }

    pub fn active_alerts(env: Env) -> Vec<Alert> {
        let ids: Vec<u64> = read_persistent_or(&env, &DataKey::ActiveAlerts, Vec::new(&env));
        let mut out = Vec::new(&env);
        for id in ids.iter() {
            if let Some(alert) = env
                .storage()
                .persistent()
                .get::<DataKey, Alert>(&DataKey::Alert(id))
            {
                if !alert.resolved {
                    out.push_back(alert);
                }
            }
        }
        out
    }

    /// Close an alert once the health centre has responded to it.
    pub fn resolve_alert(env: Env, id: u64) -> Result<(), Error> {
        require_admin(&env)?;
        bump_instance(&env);
        let mut alert: Alert = env
            .storage()
            .persistent()
            .get(&DataKey::Alert(id))
            .ok_or(Error::UnknownAlert)?;
        if !alert.resolved {
            alert.resolved = true;
            put_persistent(&env, &DataKey::Alert(id), &alert);
            let active: Vec<u64> = read_persistent_or(&env, &DataKey::ActiveAlerts, Vec::new(&env));
            let mut kept = Vec::new(&env);
            for other in active.iter() {
                if other != id {
                    kept.push_back(other);
                }
            }
            put_persistent(&env, &DataKey::ActiveAlerts, &kept);
        }
        AlertResolved {
            id,
            resolved_at: env.ledger().timestamp(),
        }
        .publish(&env);
        Ok(())
    }

    // --------------------------------------------------------- epoch lifecycle

    /// Finalise a past epoch: learn its baselines, publish a k-anonymised
    /// summary, and *delete* the raw counters and nullifier markers. After this
    /// call the epoch's individual telemetry no longer exists on chain.
    pub fn close_epoch(env: Env, epoch: u32) -> Result<Vec<SummaryCell>, Error> {
        require_admin(&env)?;
        bump_instance(&env);
        let config = read_config(&env)?;
        if epoch >= current_epoch(&env)? {
            return Err(Error::EpochTooRecent);
        }
        if env.storage().persistent().has(&DataKey::EpochClosed(epoch)) {
            return Err(Error::AlreadyClosed);
        }

        let cells: Vec<CellKey> =
            read_persistent_or(&env, &DataKey::EpochCells(epoch), Vec::new(&env));
        let mut summary = Vec::new(&env);

        for cell in cells.iter() {
            let count: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::Cell(epoch, cell.zone_id, cell.symptom))
                .unwrap_or(0);

            let baseline_key = DataKey::Baseline(cell.zone_id, cell.symptom);
            let has_baseline = env.storage().persistent().has(&baseline_key);
            let previous: u32 = env.storage().persistent().get(&baseline_key).unwrap_or(0);

            // An epoch that had to raise an alert must not be folded into the
            // baseline as if it were normal, otherwise the first outbreak would
            // permanently raise the bar for its own cell.
            let alerted: bool = env
                .storage()
                .persistent()
                .get::<DataKey, u32>(&DataKey::LastAlertEpoch(cell.zone_id, cell.symptom))
                .map(|last| last == epoch)
                .unwrap_or(false);

            let learned = if !has_baseline {
                if alerted {
                    config.baseline_floor
                } else if count > config.baseline_floor {
                    count
                } else {
                    config.baseline_floor
                }
            } else if alerted {
                previous
            } else {
                ewma(previous, count, config.baseline_alpha_bps)
            };
            put_persistent(&env, &baseline_key, &learned);

            // Erase the raw telemetry for this cell.
            env.storage()
                .persistent()
                .remove(&DataKey::Cell(epoch, cell.zone_id, cell.symptom));

            if count >= config.k_anon {
                summary.push_back(SummaryCell {
                    zone_id: cell.zone_id,
                    symptom: cell.symptom,
                    cases: count,
                });
            }
        }

        // Erase the per-epoch nullifier markers, they are only needed while the
        // epoch can still receive reports.
        let nullifiers: Vec<BytesN<32>> =
            read_persistent_or(&env, &DataKey::EpochNullifiers(epoch), Vec::new(&env));
        for nullifier in nullifiers.iter() {
            env.storage()
                .persistent()
                .remove(&DataKey::Nullifier(epoch, nullifier));
        }
        env.storage()
            .persistent()
            .remove(&DataKey::EpochNullifiers(epoch));
        env.storage()
            .persistent()
            .remove(&DataKey::EpochCells(epoch));

        put_persistent(&env, &DataKey::EpochSummary(epoch), &summary);
        put_persistent(&env, &DataKey::EpochClosed(epoch), &true);
        EpochClosed {
            epoch,
            summary: summary.clone(),
        }
        .publish(&env);
        Ok(summary)
    }

    /// Delete a retained epoch summary once the retention window has passed.
    pub fn purge_summary(env: Env, epoch: u32) -> Result<(), Error> {
        require_admin(&env)?;
        bump_instance(&env);
        if !env.storage().persistent().has(&DataKey::EpochClosed(epoch)) {
            return Err(Error::EpochTooRecent);
        }
        env.storage()
            .persistent()
            .remove(&DataKey::EpochSummary(epoch));
        EpochSummaryPurged {
            epoch,
            purged_at: env.ledger().timestamp(),
        }
        .publish(&env);
        Ok(())
    }

    // ------------------------------------------------- client helpers/audit

    /// Derive a credential leaf from a student-held secret and an issuance salt.
    pub fn derive_leaf(env: Env, credential_secret: BytesN<32>, salt: BytesN<32>) -> BytesN<32> {
        crypto::derive_leaf(&env, &credential_secret, &salt)
    }

    pub fn derive_nullifier(env: Env, leaf: BytesN<32>, epoch: u32) -> BytesN<32> {
        crypto::derive_nullifier(&env, &leaf, epoch)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive_commitment(
        env: Env,
        leaf: BytesN<32>,
        nullifier: BytesN<32>,
        symptom: u32,
        zone_id: u32,
        geocell: u64,
        epoch: u32,
    ) -> BytesN<32> {
        derive_commitment(&env, &leaf, &nullifier, symptom, zone_id, geocell, epoch)
    }

    /// Check a credential against the live credential set. Wallets and the
    /// issuer console use this to validate proofs before a report is filed.
    pub fn verify_credential(
        env: Env,
        leaf: BytesN<32>,
        index: u32,
        path: Vec<BytesN<32>>,
    ) -> bool {
        crypto::verify_merkle(&env, &leaf, index, &path, &read_root(&env))
    }

    /// Verify a report a student has *voluntarily* handed back, for example to
    /// a counsellor or in a dispute about an alert.
    ///
    /// Note that `nullifier_used` is only meaningful until `close_epoch`
    /// purges the epoch's markers; after that the epoch's k-anonymised summary
    /// is the permanent record.
    pub fn verify_disclosure(env: Env, report: Report) -> Result<Disclosure, Error> {
        read_config(&env)?;
        Ok(Disclosure {
            credential_valid: crypto::verify_merkle(
                &env,
                &report.leaf,
                report.index,
                &report.path,
                &read_root(&env),
            ),
            nullifier_bound: crypto::derive_nullifier(&env, &report.leaf, report.epoch)
                == report.nullifier,
            commitment_bound: derive_commitment(
                &env,
                &report.leaf,
                &report.nullifier,
                report.symptom,
                report.zone_id,
                report.geocell,
                report.epoch,
            ) == report.commitment,
            nullifier_used: env
                .storage()
                .persistent()
                .has(&DataKey::Nullifier(report.epoch, report.nullifier.clone())),
        })
    }
}

// ------------------------------------------------------------------ internals

/// Apply the k-anonymity mask. The only way a count leaves the contract.
fn mask(config: &Config, count: u32) -> Reading {
    if count == 0 {
        Reading::Empty
    } else if count < config.k_anon {
        Reading::Suppressed
    } else {
        Reading::Visible(count)
    }
}

/// Exponential moving average in basis points, integer only.
fn ewma(previous: u32, sample: u32, alpha_bps: u32) -> u32 {
    let inverse = 10_000u64 - alpha_bps as u64;
    let mixed = (previous as u64) * inverse + (sample as u64) * (alpha_bps as u64);
    (mixed / 10_000) as u32
}

/// Ceiling of `value * bps / 10000`.
fn mul_bps_ceil(value: u32, bps: u32) -> u32 {
    let numerator = (value as u64) * (bps as u64);
    numerator.div_ceil(10_000) as u32
}

/// Compare a live cell against its learned baseline and raise an alert if the
/// configured multiple has been crossed. Runs on every accepted report, so
/// alerts fire as soon as the signal exists, before lab confirmation.
fn evaluate_threshold(
    env: &Env,
    config: &Config,
    zone: &Zone,
    epoch: u32,
    symptom: u32,
    count: u32,
) -> Option<Alert> {
    let min_cases = if zone.min_cases > config.min_cases {
        zone.min_cases
    } else {
        config.min_cases
    };
    if count < min_cases {
        return None;
    }

    let learned: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::Baseline(zone.id, symptom))
        .unwrap_or(0);
    let baseline = if learned > config.baseline_floor {
        learned
    } else {
        config.baseline_floor
    };
    if count < mul_bps_ceil(baseline, config.multiplier_bps) {
        return None;
    }

    let last_key = DataKey::LastAlertEpoch(zone.id, symptom);
    if let Some(last) = env.storage().persistent().get::<DataKey, u32>(&last_key) {
        if epoch < last.saturating_add(config.cooldown_epochs) {
            return None;
        }
    }

    let sequence: u64 = read_instance_or(env, &DataKey::AlertSeq, 0u64);
    let id = sequence + 1;
    let alert = Alert {
        id,
        zone_id: zone.id,
        symptom,
        epoch,
        cases: count,
        baseline,
        severity_bps: ((count as u64) * 10_000 / (baseline as u64).max(1)) as u32,
        triggered_at: env.ledger().timestamp(),
        resolved: false,
    };

    put_persistent(env, &DataKey::Alert(id), &alert);
    put_persistent(env, &last_key, &epoch);
    put_instance(env, &DataKey::AlertSeq, &id);

    let mut active: Vec<u64> = read_persistent_or(env, &DataKey::ActiveAlerts, Vec::new(env));
    if active.len() >= MAX_ACTIVE_ALERTS {
        let mut trimmed = Vec::new(env);
        for index in 1..active.len() {
            trimmed.push_back(active.get(index).unwrap());
        }
        active = trimmed;
    }
    active.push_back(id);
    put_persistent(env, &DataKey::ActiveAlerts, &active);

    Some(alert)
}

fn publish_alert(env: &Env, alert: &Alert) {
    OutbreakAlert {
        id: alert.id,
        zone_id: alert.zone_id,
        symptom: alert.symptom,
        epoch: alert.epoch,
        cases: alert.cases,
        baseline: alert.baseline,
        severity_bps: alert.severity_bps,
        triggered_at: alert.triggered_at,
    }
    .publish(env);
}

fn validate_config(config: &Config) -> Result<(), Error> {
    let ok = config.k_anon >= 3
        && config.min_cases >= 1
        && config.multiplier_bps >= 10_000
        && config.multiplier_bps <= 100_000
        && config.baseline_floor >= 1
        && config.cooldown_epochs >= 1
        && config.baseline_alpha_bps >= 1
        && config.baseline_alpha_bps <= 10_000
        && config.epoch_length_secs >= 60
        && config.max_proof_depth >= 1
        && config.max_proof_depth <= 32
        && config.max_cells_per_epoch >= 1;
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidConfig)
    }
}

fn current_epoch(env: &Env) -> Result<u32, Error> {
    let config = read_config(env)?;
    let epoch = env.ledger().timestamp() / config.epoch_length_secs;
    if epoch > u32::MAX as u64 {
        return Err(Error::InvalidConfig);
    }
    Ok(epoch as u32)
}

fn read_admin(env: &Env) -> Result<Address, Error> {
    env.storage()
        .instance()
        .get(&DataKey::Admin)
        .ok_or(Error::NotInitialized)
}

fn require_admin(env: &Env) -> Result<Address, Error> {
    let admin = read_admin(env)?;
    admin.require_auth();
    Ok(admin)
}

fn read_config(env: &Env) -> Result<Config, Error> {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .ok_or(Error::NotInitialized)
}

fn read_root(env: &Env) -> BytesN<32> {
    env.storage()
        .instance()
        .get(&DataKey::CredentialRoot)
        .unwrap_or(BytesN::from_array(env, &[0u8; 32]))
}

fn read_zone(env: &Env, zone_id: u32) -> Result<Zone, Error> {
    env.storage()
        .persistent()
        .get(&DataKey::Zone(zone_id))
        .ok_or(Error::UnknownZone)
}

fn read_instance_or<V>(env: &Env, key: &DataKey, fallback: V) -> V
where
    V: TryFromVal<Env, Val> + IntoVal<Env, Val> + Clone,
    V::Error: core::fmt::Debug,
{
    env.storage().instance().get(key).unwrap_or(fallback)
}

fn read_persistent_or<V>(env: &Env, key: &DataKey, fallback: V) -> V
where
    V: TryFromVal<Env, Val> + IntoVal<Env, Val> + Clone,
    V::Error: core::fmt::Debug,
{
    env.storage().persistent().get(key).unwrap_or(fallback)
}

fn put_instance<V>(env: &Env, key: &DataKey, value: &V)
where
    V: IntoVal<Env, Val>,
{
    env.storage().instance().set(key, value);
}

fn put_persistent<V>(env: &Env, key: &DataKey, value: &V)
where
    V: IntoVal<Env, Val>,
{
    let storage = env.storage().persistent();
    storage.set(key, value);
    storage.extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND);
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
}
