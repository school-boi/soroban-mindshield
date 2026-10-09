//! Behavioural tests for the MindShield protocol.
//!
//! Two families of invariant are under test:
//!
//! * **Privacy**: k-anonymity on every read path, one report per credential per
//!   epoch, no identity or precise location on chain, raw telemetry deleted when
//!   an epoch closes, reports that need no authorisation at all.
//! * **Outbreak detection**: thresholds fire automatically mid-epoch, cooldowns
//!   suppress alert spam, and learned baselines stop a stable signal from
//!   alarming forever while a genuine spike still fires.
//!
//! The Merkle tree and every hash derivation are re-implemented independently
//! here, so the contract's crypto is cross-checked rather than trusted.

extern crate std;

use crate::events::{EpochClosed, ReportSubmitted};
use crate::types::*;
use crate::{MindShield, MindShieldClient};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::ContractEvent;
use soroban_sdk::{Address, Bytes, BytesN, Env, Event, Symbol, Vec};

/// One day, the epoch length used throughout the tests.
const EPOCH: u64 = 86_400;
/// Domain tags, mirroring `crypto`.
const TAG_NODE: u8 = 0x01;
const TAG_LEAF: u8 = 0x04;
const TAG_NULLIFIER: u8 = 0x05;
const TAG_COMMITMENT: u8 = 0x06;

const ZONE: u32 = 1;
const GEOCELL: u64 = 10;
const GEOCELL_ALT: u64 = 11;
const ZONE_OTHER: u32 = 2;
const GEOCELL_OTHER: u64 = 20;

// ---------------------------------------------------------------- test setup

fn config(env: &Env) -> Config {
    let _ = env;
    Config {
        k_anon: 3,
        min_cases: 3,
        multiplier_bps: 30_000,
        baseline_floor: 2,
        cooldown_epochs: 2,
        baseline_alpha_bps: 2_500,
        epoch_length_secs: EPOCH,
        max_proof_depth: 8,
        max_cells_per_epoch: 64,
    }
}

struct Enrollment {
    leaves: std::vec::Vec<BytesN<32>>,
    paths: std::vec::Vec<Vec<BytesN<32>>>,
}

struct Setup<'a> {
    id: Address,
    client: MindShieldClient<'a>,
    admin: Address,
    roster: Enrollment,
}

/// Deploy, initialise, register two zones and issue `roster_size` anonymous
/// credentials.
fn setup_with<'a>(env: &'a Env, cfg: Config, zone_min_cases: u32, roster_size: u32) -> Setup<'a> {
    env.mock_all_auths();
    let id = env.register(MindShield, ());
    let client = MindShieldClient::new(env, &id);
    let admin = Address::generate(env);

    client.initialize(&admin, &cfg);
    client.register_zone(
        &ZONE,
        &Symbol::new(env, "dorm_north"),
        &zone_min_cases,
        &Vec::from_slice(env, &[GEOCELL, GEOCELL_ALT]),
    );
    client.register_zone(
        &ZONE_OTHER,
        &Symbol::new(env, "dining_hall"),
        &0u32,
        &Vec::from_slice(env, &[GEOCELL_OTHER]),
    );

    let roster = enroll(env, &client, roster_size);
    let (root, _) = merkle(env, &roster.leaves);
    client.rotate_credentials(&root);

    Setup {
        id,
        client,
        admin,
        roster,
    }
}

fn setup<'a>(env: &'a Env, cfg: Config) -> Setup<'a> {
    setup_with(env, cfg, 0, 8)
}

/// Derive `count` credential leaves (a power of two) and each student's
/// inclusion path.
fn enroll(env: &Env, client: &MindShieldClient, count: u32) -> Enrollment {
    let mut leaves = std::vec::Vec::new();
    for i in 0..count {
        let secret = BytesN::from_array(env, &[i as u8 + 1; 32]);
        let salt = BytesN::from_array(env, &[0xA5; 32]);
        leaves.push(client.derive_leaf(&secret, &salt));
    }

    let (_, raw_paths) = merkle(env, &leaves);
    let mut paths = std::vec::Vec::new();
    for raw in raw_paths.iter() {
        paths.push(Vec::from_slice(env, raw));
    }
    Enrollment { leaves, paths }
}

/// Build a Merkle tree over `leaves` and return the root plus every path.
fn merkle(
    env: &Env,
    leaves: &[BytesN<32>],
) -> (BytesN<32>, std::vec::Vec<std::vec::Vec<BytesN<32>>>) {
    let mut levels: std::vec::Vec<std::vec::Vec<BytesN<32>>> = std::vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let current = levels.last().unwrap().clone();
        let mut next = std::vec::Vec::new();
        let mut i = 0;
        while i < current.len() {
            next.push(node(env, &current[i], &current[i + 1]));
            i += 2;
        }
        levels.push(next);
    }

    let root = levels.last().unwrap()[0].clone();
    let mut paths = std::vec::Vec::new();
    for index in 0..leaves.len() {
        let mut path = std::vec::Vec::new();
        let mut idx = index;
        for level in levels[..levels.len() - 1].iter() {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            path.push(level[sibling].clone());
            idx /= 2;
        }
        paths.push(path);
    }
    (root, paths)
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Independent re-implementation of the interior node hash.
fn node(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut buf = Bytes::from_array(env, &[TAG_NODE]);
    buf.append(&Bytes::from_array(env, &left.to_array()));
    buf.append(&Bytes::from_array(env, &right.to_array()));
    BytesN::from_array(env, &env.crypto().sha256(&buf).to_array())
}

/// Independent re-implementations of the protocol derivations.
fn local_leaf(env: &Env, secret: &BytesN<32>, salt: &BytesN<32>) -> BytesN<32> {
    let mut buf = Bytes::from_array(env, &[TAG_LEAF]);
    buf.append(&Bytes::from_array(env, &secret.to_array()));
    buf.append(&Bytes::from_array(env, &salt.to_array()));
    BytesN::from_array(env, &env.crypto().sha256(&buf).to_array())
}

fn local_nullifier(env: &Env, leaf: &BytesN<32>, epoch: u32) -> BytesN<32> {
    let mut buf = Bytes::from_array(env, &[TAG_NULLIFIER]);
    buf.append(&Bytes::from_array(env, &leaf.to_array()));
    buf.append(&Bytes::from_array(env, &epoch.to_be_bytes()));
    BytesN::from_array(env, &env.crypto().sha256(&buf).to_array())
}

fn local_commitment(
    env: &Env,
    leaf: &BytesN<32>,
    nullifier: &BytesN<32>,
    symptom: u32,
    zone_id: u32,
    geocell: u64,
    epoch: u32,
) -> BytesN<32> {
    let mut buf = Bytes::from_array(env, &[TAG_COMMITMENT]);
    buf.append(&Bytes::from_array(env, &leaf.to_array()));
    buf.append(&Bytes::from_array(env, &nullifier.to_array()));
    buf.append(&Bytes::from_array(env, &symptom.to_be_bytes()));
    buf.append(&Bytes::from_array(env, &zone_id.to_be_bytes()));
    buf.append(&Bytes::from_array(env, &geocell.to_be_bytes()));
    buf.append(&Bytes::from_array(env, &epoch.to_be_bytes()));
    BytesN::from_array(env, &env.crypto().sha256(&buf).to_array())
}

/// Assemble a well-formed shielded report for student `student`.
fn report(
    env: &Env,
    s: &Setup<'_>,
    student: u32,
    zone: u32,
    geocell: u64,
    symptom: u32,
    epoch: u32,
) -> Report {
    let _ = env;
    let leaf = s.roster.leaves[student as usize].clone();
    let nullifier = s.client.derive_nullifier(&leaf, &epoch);
    let commitment = s
        .client
        .derive_commitment(&leaf, &nullifier, &symptom, &zone, &geocell, &epoch);
    Report {
        zone_id: zone,
        geocell,
        symptom,
        epoch,
        leaf,
        index: student,
        path: s.roster.paths[student as usize].clone(),
        nullifier,
        commitment,
    }
}

/// File a report into the main dorm zone and return the resulting reading.
fn file(env: &Env, s: &Setup<'_>, student: u32, symptom: u32, epoch: u32) -> Reading {
    let r = report(env, s, student, ZONE, GEOCELL, symptom, epoch);
    s.client.submit_report(&r)
}

/// File reports into one cell from students `from..to`.
///
/// A credential may file exactly one report per epoch, whatever cell it lands
/// in, so tests must draw each successive cell from a disjoint student range.
fn file_range(env: &Env, s: &Setup<'_>, from: u32, to: u32, symptom: u32, epoch: u32) {
    for student in from..to {
        file(env, s, student, symptom, epoch);
    }
}

/// File `count` reports into one cell, starting from student zero.
fn file_many(env: &Env, s: &Setup<'_>, count: u32, symptom: u32, epoch: u32) {
    file_range(env, s, 0, count, symptom, epoch);
}

fn events_of(env: &Env, id: &Address) -> std::vec::Vec<ContractEvent> {
    env.events().all().filter_by_contract(id).events().to_vec()
}

// ------------------------------------------------------------------- lifecycle

#[test]
fn initialize_is_one_time() {
    let env = Env::default();
    let s = setup(&env, config(&env));
    assert_eq!(
        s.client.try_initialize(&s.admin, &config(&env)),
        Err(Ok(Error::AlreadyInitialized))
    );
}

#[test]
fn configuration_is_validated_and_readable() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(MindShield, ());
    let client = MindShieldClient::new(&env, &id);
    let admin = Address::generate(&env);

    let mut weak = config(&env);
    weak.k_anon = 2; // too small to hide anyone
    assert_eq!(
        client.try_initialize(&admin, &weak),
        Err(Ok(Error::InvalidConfig))
    );

    weak.k_anon = 3;
    weak.multiplier_bps = 9_000; // below 1x baseline would never fire
    assert_eq!(
        client.try_initialize(&admin, &weak),
        Err(Ok(Error::InvalidConfig))
    );

    weak.multiplier_bps = 30_000;
    client.initialize(&admin, &weak);
    assert_eq!(client.config(), weak);
    assert_eq!(client.admin(), admin);
    assert_eq!(client.epoch_now(), 0);

    // Parameters are tunable later, through the same validation.
    let mut tighter = weak.clone();
    tighter.k_anon = 5;
    client.set_config(&tighter);
    assert_eq!(client.config().k_anon, 5);
}

#[test]
fn zones_are_readable_but_mutated_only_by_the_admin() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    assert_eq!(s.client.zones().len(), 2);
    assert_eq!(s.client.zone(&ZONE).label, Symbol::new(&env, "dorm_north"));
    assert!(s.client.is_cell_in_zone(&ZONE, &GEOCELL));
    assert!(!s.client.is_cell_in_zone(&ZONE, &999u64));
    assert_eq!(s.client.try_zone(&42u32), Err(Ok(Error::UnknownZone)));

    // A zone id cannot be reused, at any min_cases.
    assert_eq!(
        s.client.try_register_zone(
            &ZONE,
            &Symbol::new(&env, "dupe"),
            &0u32,
            &Vec::from_slice(&env, &[77u64]),
        ),
        Err(Ok(Error::InvalidZone))
    );
    assert_eq!(
        s.client
            .try_register_zone(&3u32, &Symbol::new(&env, "empty"), &0u32, &Vec::new(&env)),
        Err(Ok(Error::InvalidZone))
    );

    // Extending the geofence works, and the new cell becomes usable.
    s.client
        .add_zone_cells(&ZONE, &Vec::from_slice(&env, &[12u64]));
    assert!(s.client.is_cell_in_zone(&ZONE, &12u64));
    let widened = report(&env, &s, 0, ZONE, 12, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.submit_report(&widened), Reading::Suppressed);

    // With no authorisations available, admin-only entry points cannot run.
    env.set_auths(&[]);
    assert!(s.client.try_set_zone_active(&ZONE, &false).is_err());
    assert!(s.client.try_close_epoch(&0u32).is_err());
    assert!(s
        .client
        .try_rotate_credentials(&BytesN::from_array(&env, &[7u8; 32]))
        .is_err());
    assert!(s.client.try_add_zone_cells(&ZONE, &Vec::new(&env)).is_err());
}

// --------------------------------------------------------------- geofencing

#[test]
fn geofence_rejects_unknown_zones_and_unlisted_cells() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    let unknown_zone = report(&env, &s, 0, 99, GEOCELL, SYMPTOM_FEVER, 0);
    assert_eq!(
        s.client.try_submit_report(&unknown_zone),
        Err(Ok(Error::UnknownZone))
    );

    let outside = report(&env, &s, 0, ZONE, 999, SYMPTOM_FEVER, 0);
    assert_eq!(
        s.client.try_submit_report(&outside),
        Err(Ok(Error::CellNotInZone))
    );

    // A cell that belongs to another zone is not accepted here either, so a
    // precise location cannot be smuggled in through a neighbouring zone.
    let cross_zone = report(&env, &s, 0, ZONE_OTHER, GEOCELL, SYMPTOM_FEVER, 0);
    assert_eq!(
        s.client.try_submit_report(&cross_zone),
        Err(Ok(Error::CellNotInZone))
    );
}

#[test]
fn inactive_zone_refuses_new_reports_but_keeps_its_history() {
    let env = Env::default();
    let s = setup(&env, config(&env));
    file(&env, &s, 0, SYMPTOM_FEVER, 0);
    s.client.set_zone_active(&ZONE, &false);

    let r = report(&env, &s, 1, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.try_submit_report(&r), Err(Ok(Error::ZoneInactive)));

    // Readings recorded before deactivation are still served.
    assert_eq!(
        s.client.cell_reading(&ZONE, &SYMPTOM_FEVER, &0u32),
        Reading::Suppressed
    );

    s.client.set_zone_active(&ZONE, &true);
    file(&env, &s, 1, SYMPTOM_FEVER, 0);
}

#[test]
fn only_coarse_symptom_classes_are_accepted() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    for bad in [0u32, MAX_SYMPTOM_CLASS + 1] {
        let r = report(&env, &s, 0, ZONE, GEOCELL, bad, 0);
        assert_eq!(
            s.client.try_submit_report(&r),
            Err(Ok(Error::InvalidSymptom))
        );
    }
}

// -------------------------------------------------------------- credentials

#[test]
fn forged_credentials_are_rejected() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    // A leaf that is not in the credential set.
    let mut outsider = report(&env, &s, 0, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    outsider.leaf = BytesN::from_array(&env, &[0xEE; 32]);
    assert_eq!(
        s.client.try_submit_report(&outsider),
        Err(Ok(Error::InvalidProof))
    );

    // A legitimately issued leaf with a tampered inclusion path.
    let mut tampered = report(&env, &s, 1, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    let mut path = tampered.path.clone();
    path.set(0, BytesN::from_array(&env, &[0x11; 32]));
    tampered.path = path;
    assert_eq!(
        s.client.try_submit_report(&tampered),
        Err(Ok(Error::InvalidProof))
    );

    // The eligibility check is also exposed for wallets and issuers.
    assert!(s
        .client
        .verify_credential(&s.roster.leaves[6], &6u32, &s.roster.paths[6]));
    assert!(!s.client.verify_credential(
        &BytesN::from_array(&env, &[0xEE; 32]),
        &0u32,
        &s.roster.paths[0],
    ));
    assert_eq!(s.client.credential_root(), {
        let (root, _) = merkle(&env, &s.roster.leaves);
        root
    });
}

#[test]
fn proof_depth_is_bounded() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    let mut deep = report(&env, &s, 0, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    let mut path = deep.path.clone();
    while path.len() <= 8 {
        path.push_back(BytesN::from_array(&env, &[0x22; 32]));
    }
    deep.path = path;
    assert_eq!(
        s.client.try_submit_report(&deep),
        Err(Ok(Error::ProofTooDeep))
    );
}

#[test]
fn nullifier_and_commitment_must_bind_the_credential() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    // A nullifier borrowed from another epoch.
    let mut stolen = report(&env, &s, 0, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    stolen.nullifier = s.client.derive_nullifier(&stolen.leaf, &7u32);
    assert_eq!(
        s.client.try_submit_report(&stolen),
        Err(Ok(Error::BadNullifier))
    );

    // A commitment that does not cover the reported symptom.
    let mut mismatched = report(&env, &s, 0, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    mismatched.commitment = s.client.derive_commitment(
        &mismatched.leaf,
        &mismatched.nullifier,
        &SYMPTOM_GASTROINTESTINAL,
        &ZONE,
        &GEOCELL,
        &0u32,
    );
    assert_eq!(
        s.client.try_submit_report(&mismatched),
        Err(Ok(Error::BadCommitment))
    );
}

#[test]
fn one_report_per_credential_per_epoch() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    assert_eq!(file(&env, &s, 3, SYMPTOM_FEVER, 0), Reading::Suppressed);

    // Same credential, same epoch: refused, so one student cannot stuff a
    // counter and fabricate an outbreak.
    let repeat = report(&env, &s, 3, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    assert_eq!(
        s.client.try_submit_report(&repeat),
        Err(Ok(Error::DuplicateReport))
    );

    // Another credential is fine, and the same student may report again in a
    // later epoch, which is what makes repeat symptom tracking possible.
    file(&env, &s, 4, SYMPTOM_FEVER, 0);

    // The rule is one report per credential per epoch, not per cell, so a
    // student cannot inflate several zones at once with a single credential.
    let cross_cell = report(&env, &s, 4, ZONE, GEOCELL_ALT, SYMPTOM_GASTROINTESTINAL, 0);
    assert_eq!(
        s.client.try_submit_report(&cross_cell),
        Err(Ok(Error::DuplicateReport))
    );

    env.ledger().set_timestamp(EPOCH);
    file(&env, &s, 3, SYMPTOM_FEVER, 1);
}

#[test]
fn reporting_requires_no_authorisation_and_leaks_no_credential() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    // Drop every mocked authorisation: a report carries no signature at all,
    // which is what makes purely anonymous, relayed submission possible.
    env.set_auths(&[]);
    let r = report(&env, &s, 5, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.submit_report(&r), Reading::Suppressed);

    // The only thing published is an opaque commitment: the credential leaf
    // that proves eligibility is not in the event, and neither is any address.
    let expected = ReportSubmitted {
        epoch: 0,
        zone_id: ZONE,
        symptom: SYMPTOM_FEVER,
        commitment: r.commitment.clone(),
    };
    assert_eq!(
        events_of(&env, &s.id),
        std::vec![expected.to_xdr(&env, &s.id)]
    );
}

#[test]
fn epoch_window_rejects_backdating_and_closed_epochs() {
    let env = Env::default();
    let s = setup(&env, config(&env));
    env.ledger().set_timestamp(EPOCH * 3);

    let old = report(&env, &s, 0, ZONE, GEOCELL, SYMPTOM_FEVER, 1);
    assert_eq!(
        s.client.try_submit_report(&old),
        Err(Ok(Error::EpochOutOfWindow))
    );

    let future = report(&env, &s, 0, ZONE, GEOCELL, SYMPTOM_FEVER, 4);
    assert_eq!(
        s.client.try_submit_report(&future),
        Err(Ok(Error::EpochOutOfWindow))
    );

    // The previous epoch is still writable, which tolerates relay latency.
    file(&env, &s, 0, SYMPTOM_FEVER, 2);

    // Once an epoch is closed it accepts nothing further.
    s.client.close_epoch(&2u32);
    assert_eq!(
        s.client
            .try_submit_report(&report(&env, &s, 1, ZONE, GEOCELL, SYMPTOM_FEVER, 2)),
        Err(Ok(Error::EpochClosed))
    );
}

// -------------------------------------------------------------- k-anonymity

#[test]
fn counts_below_k_are_never_returned() {
    let env = Env::default();
    let s = setup(&env, config(&env)); // k_anon = 3

    assert_eq!(
        s.client.cell_reading(&ZONE, &SYMPTOM_FEVER, &0u32),
        Reading::Empty
    );

    // One and two reports stay hidden, in the reading and in the summary alike.
    assert_eq!(file(&env, &s, 0, SYMPTOM_FEVER, 0), Reading::Suppressed);
    assert_eq!(file(&env, &s, 1, SYMPTOM_FEVER, 0), Reading::Suppressed);
    assert_eq!(
        s.client.cell_reading(&ZONE, &SYMPTOM_FEVER, &0u32),
        Reading::Suppressed
    );
    assert_eq!(s.client.summary(&0u32).len(), 0);

    // The third report is what makes the cell publishable at k_anon = 3.
    assert_eq!(file(&env, &s, 2, SYMPTOM_FEVER, 0), Reading::Visible(3));
    assert_eq!(
        s.client.cell_reading(&ZONE, &SYMPTOM_FEVER, &0u32),
        Reading::Visible(3)
    );
    let summary = s.client.summary(&0u32);
    assert_eq!(summary.len(), 1);
    assert_eq!(summary.get(0).unwrap().zone_id, ZONE);
    assert_eq!(summary.get(0).unwrap().symptom, SYMPTOM_FEVER);
    assert_eq!(summary.get(0).unwrap().cases, 3);
}

#[test]
fn cells_are_scoped_by_zone_symptom_and_epoch() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    // Three reports, but spread across zones and epochs, so every cell stays
    // under k and nothing becomes visible.
    file(&env, &s, 0, SYMPTOM_FEVER, 0);
    file(&env, &s, 1, SYMPTOM_FEVER, 0);
    let other_zone = report(&env, &s, 2, ZONE_OTHER, GEOCELL_OTHER, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.submit_report(&other_zone), Reading::Suppressed);

    env.ledger().set_timestamp(EPOCH);
    file(&env, &s, 3, SYMPTOM_FEVER, 1);

    assert_eq!(s.client.summary(&0u32).len(), 0);
    assert_eq!(s.client.summary(&1u32).len(), 0);
    assert_eq!(
        s.client.cell_reading(&ZONE_OTHER, &SYMPTOM_FEVER, &0u32),
        Reading::Suppressed
    );
    assert_eq!(
        s.client.cell_reading(&ZONE, &SYMPTOM_FEVER, &1u32),
        Reading::Suppressed
    );
}

#[test]
fn per_epoch_cell_cap_is_enforced_without_burning_the_credential() {
    let env = Env::default();
    let mut cfg = config(&env);
    cfg.max_cells_per_epoch = 1;
    let s = setup(&env, cfg);

    file(&env, &s, 0, SYMPTOM_FEVER, 0);

    let second_cell = report(&env, &s, 1, ZONE, GEOCELL, SYMPTOM_GASTROINTESTINAL, 0);
    assert_eq!(
        s.client.try_submit_report(&second_cell),
        Err(Ok(Error::CellLimitReached))
    );

    // The rejected report did not burn its credential's one-time tag, so the
    // student can still report later (for example in the next epoch).
    let proven = s.client.verify_disclosure(&second_cell);
    assert!(proven.credential_valid);
    assert!(proven.commitment_bound);
    assert!(!proven.nullifier_used);

    env.ledger().set_timestamp(EPOCH);
    let retry = report(&env, &s, 1, ZONE, GEOCELL, SYMPTOM_GASTROINTESTINAL, 1);
    assert_eq!(s.client.submit_report(&retry), Reading::Suppressed);
}

// ------------------------------------------------------- automatic alerts

#[test]
fn alert_fires_automatically_when_the_multiple_is_crossed() {
    let env = Env::default();
    let mut cfg = config(&env);
    cfg.min_cases = 3;
    cfg.multiplier_bps = 20_000; // 2x baseline
    cfg.baseline_floor = 2; // effective threshold: 4 cases
    let s = setup(&env, cfg);

    file_many(&env, &s, 3, SYMPTOM_FEVER, 0);
    assert!(!s.client.alerting(&ZONE, &SYMPTOM_FEVER));
    assert_eq!(s.client.active_alerts().len(), 0);

    // The fourth case in the epoch crosses 2x the floor. Events are read
    // immediately, because the buffer only holds the last invocation.
    let fourth = report(&env, &s, 3, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.submit_report(&fourth), Reading::Visible(4));
    let events = events_of(&env, &s.id);

    let alerts = s.client.active_alerts();
    assert_eq!(alerts.len(), 1);
    let alert = alerts.get(0).unwrap();
    assert_eq!(alert.id, 1);
    assert_eq!(alert.zone_id, ZONE);
    assert_eq!(alert.symptom, SYMPTOM_FEVER);
    assert_eq!(alert.epoch, 0);
    assert_eq!(alert.cases, 4);
    assert_eq!(alert.baseline, 2);
    assert_eq!(alert.severity_bps, 20_000);
    assert!(!alert.resolved);
    assert!(s.client.alerting(&ZONE, &SYMPTOM_FEVER));
    assert_eq!(s.client.alerts(&1u64, &10u32).len(), 1);

    // It is published, not merely stored, so off-chain monitors see it live.
    let expected = crate::events::OutbreakAlert {
        id: 1,
        zone_id: ZONE,
        symptom: SYMPTOM_FEVER,
        epoch: 0,
        cases: 4,
        baseline: 2,
        severity_bps: 20_000,
        triggered_at: 0,
    };
    assert_eq!(events.len(), 2);
    assert_eq!(events[1], expected.to_xdr(&env, &s.id));
}

#[test]
fn per_zone_min_cases_override_is_honoured() {
    let env = Env::default();
    let mut cfg = config(&env);
    cfg.min_cases = 3;
    cfg.multiplier_bps = 10_000; // only the absolute floor matters here
    cfg.baseline_floor = 1;
    // The dorm zone raises its own bar to 5 cases.
    let s = setup_with(&env, cfg, 5, 8);

    file_many(&env, &s, 4, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.active_alerts().len(), 0);

    file(&env, &s, 4, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.active_alerts().len(), 1);
    assert_eq!(s.client.active_alerts().get(0).unwrap().cases, 5);
}

#[test]
fn cooldown_prevents_alert_spam() {
    let env = Env::default();
    let mut cfg = config(&env);
    cfg.min_cases = 3;
    cfg.multiplier_bps = 20_000;
    cfg.baseline_floor = 2;
    cfg.cooldown_epochs = 2;
    let s = setup_with(&env, cfg, 0, 16);

    file_range(&env, &s, 0, 4, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.active_alerts().len(), 1);

    // More cases in the same epoch do not raise a second alert.
    file_range(&env, &s, 4, 6, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.active_alerts().len(), 1);

    // Nor does a whole epoch inside the cooldown window.
    env.ledger().set_timestamp(EPOCH);
    file_range(&env, &s, 0, 5, SYMPTOM_FEVER, 1);
    assert_eq!(s.client.active_alerts().len(), 1);

    // After the cooldown elapses a fresh alert is allowed.
    env.ledger().set_timestamp(EPOCH * 2);
    file_range(&env, &s, 0, 5, SYMPTOM_FEVER, 2);
    let alerts = s.client.alerts(&1u64, &10u32);
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts.get(1).unwrap().epoch, 2);
}

#[test]
fn alerts_can_be_resolved() {
    let env = Env::default();
    let mut cfg = config(&env);
    cfg.min_cases = 3;
    cfg.multiplier_bps = 20_000;
    cfg.baseline_floor = 2;
    let s = setup(&env, cfg);

    file_many(&env, &s, 4, SYMPTOM_FEVER, 0);
    assert!(s.client.alerting(&ZONE, &SYMPTOM_FEVER));
    assert_eq!(s.client.try_alert(&9u64), Err(Ok(Error::UnknownAlert)));
    assert_eq!(
        s.client.try_resolve_alert(&9u64),
        Err(Ok(Error::UnknownAlert))
    );

    s.client.resolve_alert(&1u64);
    assert!(!s.client.alerting(&ZONE, &SYMPTOM_FEVER));
    assert_eq!(s.client.active_alerts().len(), 0);
    assert!(s.client.alert(&1u64).resolved);

    // Resolving twice is harmless, and the audit trail keeps the alert.
    s.client.resolve_alert(&1u64);
    assert_eq!(s.client.alerts(&1u64, &10u32).len(), 1);
}

// ------------------------------------------------------ epoch close/privacy

#[test]
fn close_epoch_purges_raw_telemetry_and_keeps_only_k_anonymous_cells() {
    let env = Env::default();
    let s = setup(&env, config(&env));
    env.ledger().set_timestamp(EPOCH);

    // One cell that clears k, one that never does. Each cell draws on its own
    // students, because a credential may only report once per epoch.
    file_range(&env, &s, 0, 3, SYMPTOM_FEVER, 1);
    file_range(&env, &s, 3, 5, SYMPTOM_GASTROINTESTINAL, 1);

    env.ledger().set_timestamp(EPOCH * 2);
    let summary = s.client.close_epoch(&1u32);
    let events = events_of(&env, &s.id);
    assert_eq!(summary.len(), 1);
    assert_eq!(summary.get(0).unwrap().symptom, SYMPTOM_FEVER);
    assert_eq!(summary.get(0).unwrap().cases, 3);

    // The k-anonymised cell survives, and the close is announced.
    assert_eq!(
        s.client.cell_reading(&ZONE, &SYMPTOM_FEVER, &1u32),
        Reading::Visible(3)
    );
    assert_eq!(s.client.summary(&1u32).len(), 1);
    let expected = EpochClosed {
        epoch: 1,
        summary: summary.clone(),
    };
    assert_eq!(events, std::vec![expected.to_xdr(&env, &s.id)]);

    // The sub-k cell's raw counter is gone: purged, and never summarised.
    assert_eq!(
        s.client
            .cell_reading(&ZONE, &SYMPTOM_GASTROINTESTINAL, &1u32),
        Reading::Empty
    );

    // Closing is idempotent-safe: it refuses a second pass.
    assert_eq!(
        s.client.try_close_epoch(&1u32),
        Err(Ok(Error::AlreadyClosed))
    );
}

#[test]
fn close_epoch_learns_baselines() {
    let env = Env::default();
    let mut cfg = config(&env);
    cfg.baseline_floor = 2;
    cfg.baseline_alpha_bps = 6_000;
    let s = setup_with(&env, cfg, 0, 8);

    assert_eq!(s.client.baseline_of(&ZONE, &SYMPTOM_FEVER), 0);
    env.ledger().set_timestamp(EPOCH);
    file_range(&env, &s, 0, 3, SYMPTOM_FEVER, 1);
    file_range(&env, &s, 3, 5, SYMPTOM_GASTROINTESTINAL, 1);

    env.ledger().set_timestamp(EPOCH * 2);
    s.client.close_epoch(&1u32);

    // The busier cell seeds its own baseline, the quieter one matches the
    // floor rather than being pushed to zero.
    assert_eq!(s.client.baseline_of(&ZONE, &SYMPTOM_FEVER), 3);
    assert_eq!(s.client.baseline_of(&ZONE, &SYMPTOM_GASTROINTESTINAL), 2);

    // A second, comparable epoch is blended in through the moving average.
    file_many(&env, &s, 5, SYMPTOM_FEVER, 2);
    env.ledger().set_timestamp(EPOCH * 3);
    s.client.close_epoch(&2u32);
    // ewma(3, 5, 6000) = (3*4000 + 5*6000) / 10000 = 4
    assert_eq!(s.client.baseline_of(&ZONE, &SYMPTOM_FEVER), 4);
}

#[test]
fn baselines_adapt_so_a_stable_signal_stops_alerting() {
    let env = Env::default();
    let mut cfg = config(&env);
    cfg.min_cases = 3;
    cfg.multiplier_bps = 20_000; // 2x
    cfg.baseline_floor = 3; // first-epoch threshold: 6 cases
    cfg.baseline_alpha_bps = 6_000;
    let s = setup_with(&env, cfg, 0, 8);

    // Epoch 0: five cases, one short of the 6-case threshold.
    file_many(&env, &s, 5, SYMPTOM_FEVER, 0);
    assert_eq!(s.client.active_alerts().len(), 0);

    env.ledger().set_timestamp(EPOCH);
    s.client.close_epoch(&0u32);
    assert_eq!(s.client.baseline_of(&ZONE, &SYMPTOM_FEVER), 5);

    // Epoch 1: seven cases. That exceeds the *original* threshold of 6, but the
    // learnt baseline has raised the bar to 10, so this stable level is now
    // recognised as normal rather than as a fresh outbreak.
    file_many(&env, &s, 7, SYMPTOM_FEVER, 1);
    assert_eq!(
        s.client.cell_reading(&ZONE, &SYMPTOM_FEVER, &1u32),
        Reading::Visible(7)
    );
    assert_eq!(s.client.active_alerts().len(), 0);
    assert!(!s.client.alerting(&ZONE, &SYMPTOM_FEVER));
}

#[test]
fn a_genuine_spike_still_alerts_after_learning() {
    let env = Env::default();
    let mut cfg = config(&env);
    cfg.min_cases = 3;
    cfg.multiplier_bps = 20_000; // 2x
    cfg.baseline_floor = 3;
    cfg.baseline_alpha_bps = 6_000;
    let s = setup_with(&env, cfg, 0, 32);

    file_many(&env, &s, 5, SYMPTOM_FEVER, 0);
    env.ledger().set_timestamp(EPOCH);
    s.client.close_epoch(&0u32);
    assert_eq!(s.client.baseline_of(&ZONE, &SYMPTOM_FEVER), 5);

    // A sevenfold jump over the learned baseline fires mid-epoch, at the
    // moment the threshold is crossed rather than at end of day.
    file_many(&env, &s, 12, SYMPTOM_FEVER, 1);
    let alerts = s.client.active_alerts();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts.get(0).unwrap().cases, 10);
    assert_eq!(alerts.get(0).unwrap().baseline, 5);
    assert_eq!(alerts.get(0).unwrap().severity_bps, 20_000);
}

#[test]
fn summary_retention_can_be_purged() {
    let env = Env::default();
    let s = setup(&env, config(&env));
    env.ledger().set_timestamp(EPOCH);
    file_many(&env, &s, 3, SYMPTOM_FEVER, 1);
    env.ledger().set_timestamp(EPOCH * 2);
    s.client.close_epoch(&1u32);
    assert_eq!(s.client.summary(&1u32).len(), 1);

    // A live epoch has nothing to purge.
    assert_eq!(
        s.client.try_purge_summary(&2u32),
        Err(Ok(Error::EpochTooRecent))
    );

    s.client.purge_summary(&1u32);
    assert_eq!(s.client.summary(&1u32).len(), 0);
    assert_eq!(
        s.client.cell_reading(&ZONE, &SYMPTOM_FEVER, &1u32),
        Reading::Empty
    );
}

#[test]
fn close_epoch_requires_a_past_epoch() {
    let env = Env::default();
    let s = setup(&env, config(&env));
    assert_eq!(
        s.client.try_close_epoch(&0u32),
        Err(Ok(Error::EpochTooRecent))
    );
}

// ------------------------------------------------------- crypto/audit views

#[test]
fn derivations_match_an_independent_implementation() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    let secret = BytesN::from_array(&env, &[0x42; 32]);
    let salt = BytesN::from_array(&env, &[0x24; 32]);

    let leaf = s.client.derive_leaf(&secret, &salt);
    assert_eq!(leaf, local_leaf(&env, &secret, &salt));

    let nullifier = s.client.derive_nullifier(&leaf, &9u32);
    assert_eq!(nullifier, local_nullifier(&env, &leaf, 9));
    // The tag is epoch-scoped: the same credential cannot be counted twice.
    assert_ne!(nullifier, local_nullifier(&env, &leaf, 10));

    let commitment =
        s.client
            .derive_commitment(&leaf, &nullifier, &SYMPTOM_FEVER, &ZONE, &GEOCELL, &9u32);
    assert_eq!(
        commitment,
        local_commitment(&env, &leaf, &nullifier, SYMPTOM_FEVER, ZONE, GEOCELL, 9)
    );
}

#[test]
fn reference_client_matches_the_contract() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    // `enroll` uses the same inputs, so the root published by
    // `tools/mindshield_client.py enroll --students 8 --salt 0xA5` must be the
    // root the contract derives. This pins the off-chain reference client (and
    // therefore the documented domain tags) to the Rust implementation.
    let (root, paths) = merkle(&env, &s.roster.leaves);
    assert_eq!(
        root,
        BytesN::from_array(
            &env,
            &hex32("fe06da5e0cac187146a33708e42421348d1bdc023cbade5014967efa31a5d278")
        )
    );
    let path = Vec::from_slice(&env, &paths[6]);
    assert!(s
        .client
        .verify_credential(&s.roster.leaves[6], &6u32, &path));
    assert_eq!(s.client.credential_root(), root);
}

#[test]
fn verify_disclosure_round_trip() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    let r = report(&env, &s, 2, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    s.client.submit_report(&r);

    // A student who chooses to disclose can prove their report was well formed.
    let proven = s.client.verify_disclosure(&r);
    assert!(proven.credential_valid);
    assert!(proven.nullifier_bound);
    assert!(proven.commitment_bound);
    assert!(proven.nullifier_used);

    // Tampering with any field breaks the proof, so disclosure cannot be
    // used to claim somebody else's report.
    let mut forged = r.clone();
    forged.commitment = BytesN::from_array(&env, &[0x01; 32]);
    let proven = s.client.verify_disclosure(&forged);
    assert!(proven.credential_valid);
    assert!(proven.nullifier_bound);
    assert!(!proven.commitment_bound);

    let mut wrong_epoch = r.clone();
    wrong_epoch.epoch = 1;
    let proven = s.client.verify_disclosure(&wrong_epoch);
    assert!(!proven.nullifier_bound);
}

#[test]
fn undisclosed_credentials_are_not_traceable_through_events() {
    let env = Env::default();
    let s = setup(&env, config(&env));

    // Two students report into the same cell in the same epoch.
    let first = report(&env, &s, 0, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    let second = report(&env, &s, 1, ZONE, GEOCELL, SYMPTOM_FEVER, 0);
    s.client.submit_report(&first);
    let first_events = events_of(&env, &s.id);
    s.client.submit_report(&second);

    // The published payloads are opaque commitments, and they differ, so the
    // event log cannot be joined back to a credential by inspection.
    assert_eq!(first_events.len(), 1);
    assert_ne!(first.commitment, second.commitment);
    assert_ne!(first.commitment, first.leaf);
    assert_ne!(second.commitment, second.leaf);
}
