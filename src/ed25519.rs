//! Threshold-controlled Ed25519 accounts, provisioned in one call.
//!
//! A treasury is an account no single person can spend from: `t` of `n`
//! holders must agree. Zyn already had every piece needed for one — the DKG is
//! generic over ciphersuite, `frost-ed25519` was already a dependency, and the
//! VM accepts an ordinary Ed25519 signature. What it lacked was a name for the
//! combination, so provisioning one looked like new cryptography when it was
//! assembly.
//!
//! # Why no VM change is needed
//!
//! A FROST group over Ed25519 produces an **ordinary** Ed25519 signature
//! against an **ordinary** Ed25519 verifying key. The chain cannot tell — and
//! does not need to tell — whether one key signed or five cooperated. So a
//! treasury is a normal [`Scheme::Ed25519`] account, and every existing
//! authorisation path works unchanged.
//!
//! # Using it for the next project
//!
//! ```ignore
//! let t = Treasury::provision(2, 3)?;   // 2-of-3
//! let account = t.account;              // pin this; it is the identity
//! // distribute t.shares, one per holder, and never keep two together
//! ```
//!
//! The same call serves a protocol treasury, a project's raise, or a grant
//! pool. Only `threshold` and `participants` change.

use std::collections::BTreeMap;

pub use frost_core::keys::PublicKeyPackage;

use crate::ceremony::{CeremonyError, IdentifierFor, ThresholdKeys};

/// The ciphersuite a threshold-controlled Zyn account uses: plain Ed25519, so
/// the group's signature is indistinguishable from a single signer's.
pub type Ed25519Suite = frost_ed25519::Ed25519Sha512;

/// A provisioned treasury: the account it speaks for, and one share per holder.
pub struct Treasury {
    /// The 32-byte Zyn account. Pin this — it is the treasury's identity, and
    /// every address derived from it moves if it changes.
    pub account: [u8; 32],
    /// The group verifying key, as the chain will see it.
    pub group_key: [u8; 32],
    /// One share per holder. **Never store two in one place** — that is the
    /// whole point of the threshold.
    pub shares: BTreeMap<IdentifierFor<Ed25519Suite>, ThresholdKeys<Ed25519Suite>>,
}

impl Treasury {
    /// Run the ceremony and return the account plus its shares.
    ///
    /// This drives the DKG in memory, which is right for provisioning where the
    /// participants are machines an operator already controls. A ceremony
    /// across mutually distrusting holders uses the same rounds over the
    /// network — [`crate::dkg_net::DkgParticipant`] — and produces the same
    /// result; this is the reference for it.
    pub fn provision(threshold: u16, participants: u16) -> Result<Treasury, CeremonyError> {
        if threshold < 2 || threshold > participants {
            return Err(CeremonyError::Crypto);
        }
        let shares = crate::dkg_net::run_in_memory_for::<Ed25519Suite>(threshold, participants)?;
        let public = shares
            .values()
            .next()
            .ok_or(CeremonyError::Crypto)?
            .public_package
            .clone();
        let group_key = group_key_bytes(&public)?;
        Ok(Treasury { account: account_of_group(&public)?, group_key, shares })
    }
}

/// The group's verifying key as the 32 bytes the chain sees.
pub fn group_key_bytes(public: &PublicKeyPackage<Ed25519Suite>) -> Result<[u8; 32], CeremonyError> {
    public
        .verifying_key()
        .serialize()
        .map_err(|_| CeremonyError::Crypto)?
        .try_into()
        .map_err(|_| CeremonyError::Crypto)
}

/// The account a threshold group speaks for.
///
/// Identical to what a single Ed25519 key would produce for the same verifying
/// key, which is exactly why the VM needs no threshold-specific path.
pub fn account_of_group(public: &PublicKeyPackage<Ed25519Suite>) -> Result<[u8; 32], CeremonyError> {
    Ok(crate::account::account_of(
        crate::account::Scheme::Ed25519,
        &group_key_bytes(public)?,
    ))
}

/// Threshold-sign `message` with the named holders' shares.
///
/// Returns the group verifying key and an ordinary 64-byte Ed25519 signature —
/// everything a caller needs to build a submission frame, and nothing about
/// FROST. Each signer commits a fresh nonce to *this* message, so a nonce
/// committed to one message cannot be reused for another; that is what stops an
/// untrusted coordinator swapping the payload between rounds.
pub fn sign(
    shares: &BTreeMap<IdentifierFor<Ed25519Suite>, ThresholdKeys<Ed25519Suite>>,
    signers: &[IdentifierFor<Ed25519Suite>],
    message: &[u8],
) -> Result<([u8; 32], [u8; 64]), CeremonyError> {
    let mut rng = rand::rngs::OsRng;
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in signers {
        let keys = shares.get(id).ok_or(CeremonyError::Crypto)?;
        let (n, c) = frost_ed25519::round1::commit(keys.key_package.signing_share(), &mut rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let package = frost_ed25519::SigningPackage::new(commitments, message);

    let mut sig_shares = BTreeMap::new();
    for id in signers {
        let keys = shares.get(id).ok_or(CeremonyError::Crypto)?;
        let share = frost_ed25519::round2::sign(&package, &nonces[id], &keys.key_package)
            .map_err(|_| CeremonyError::Crypto)?;
        sig_shares.insert(*id, share);
    }

    let public = &shares.values().next().ok_or(CeremonyError::Crypto)?.public_package;
    let sig = frost_ed25519::aggregate(&package, &sig_shares, public)
        .map_err(|_| CeremonyError::Crypto)?;
    let bytes: [u8; 64] = sig
        .serialize()
        .map_err(|_| CeremonyError::Crypto)?
        .try_into()
        .map_err(|_| CeremonyError::Crypto)?;
    Ok((group_key_bytes(public)?, bytes))
}


/// Threshold-sign across custodians that each hold one share.
///
/// [`sign`] needs every share in one process, which is exactly what the
/// ceremony spent effort avoiding. This drives the same two rounds over the
/// network instead: each custodian commits a nonce to *this* payload, the
/// coordinator builds the signing package, and each returns a signature share.
///
/// The coordinator never sees a key — only commitments and signature shares,
/// and neither reconstructs one. That is what lets an untrusted process drive
/// a threshold signature.
pub fn sign_across(
    custodians: &[String],
    public: &PublicKeyPackage<Ed25519Suite>,
    threshold: usize,
    message: &[u8],
    request_id: u64,
) -> Result<([u8; 32], [u8; 64]), CeremonyError> {
    use crate::custody_net as net;

    let r1 = net::encode_treasury_round1(request_id, message);
    let mut commitments = BTreeMap::new();
    for addr in custodians {
        let Ok(reply) = net::ask(addr, &r1) else { continue };
        if let Some((id, c)) = net::read_ed25519_commitments(&reply) {
            commitments.insert(id, c);
        }
        if commitments.len() == threshold {
            break;
        }
    }
    if commitments.len() < threshold {
        return Err(CeremonyError::Crypto);
    }

    let package = frost_ed25519::SigningPackage::new(commitments.clone(), message);
    let r2 = net::encode_treasury_round2(request_id, &package).map_err(|_| CeremonyError::Crypto)?;
    let mut shares = BTreeMap::new();
    for addr in custodians {
        let Ok(reply) = net::ask(addr, &r2) else { continue };
        if let Some((id, share)) = net::read_ed25519_share(&reply) {
            if commitments.contains_key(&id) {
                shares.insert(id, share);
            }
        }
    }
    if shares.len() < threshold {
        return Err(CeremonyError::Crypto);
    }

    let sig = frost_ed25519::aggregate(&package, &shares, public).map_err(|_| CeremonyError::Crypto)?;
    let bytes: [u8; 64] = sig
        .serialize()
        .map_err(|_| CeremonyError::Crypto)?
        .try_into()
        .map_err(|_| CeremonyError::Crypto)?;
    Ok((group_key_bytes(public)?, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole split exists for: two custodians on separate
    /// sockets, each holding one share, produce a signature the chain accepts —
    /// and the coordinator driving them never holds a key.
    #[test]
    fn two_custodians_on_sockets_sign_without_the_coordinator_holding_a_key() {
        use crate::custody_net::{serve, Custodian};
        let t = Treasury::provision(2, 3).expect("provision");
        let public = t.shares.values().next().unwrap().public_package.clone();

        // One custodian per share, each on its own port, each holding one.
        let mut addrs = Vec::new();
        for keys in t.shares.values() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            addrs.push(format!("127.0.0.1:{}", listener.local_addr().unwrap().port()));
            let c = Custodian {
                zcash: None,
                ed25519: None,
                treasury: Some(crate::custodian::ed25519::Participant::new(keys.clone())),
            };
            let shared = std::sync::Arc::new(std::sync::Mutex::new(c));
            std::thread::spawn(move || serve(shared, listener, || 0));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));

        let msg = b"an intent payload";
        let (group, sig) = sign_across(&addrs, &public, 2, msg, 1).expect("sign across");

        assert_eq!(group, t.group_key);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&group).unwrap();
        vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("an ordinary verification must accept the distributed signature");
        assert_eq!(
            crate::account::account_of(crate::account::Scheme::Ed25519, &group),
            t.account,
            "and it speaks for the treasury account"
        );
    }

    #[test]
    fn provisioning_yields_an_account_and_one_share_per_holder() {
        let t = Treasury::provision(2, 3).expect("provision");
        assert_eq!(t.shares.len(), 3, "one share per holder");
        assert_ne!(t.account, [0u8; 32], "a zero account is the unprovisioned sentinel");
        // Every holder agrees which account they are custodians of.
        for keys in t.shares.values() {
            assert_eq!(account_of_group(&keys.public_package).unwrap(), t.account);
        }
    }

    /// The property that means the chain needs no threshold-aware code: the
    /// account is what a single Ed25519 key with the same verifying key would
    /// produce.
    #[test]
    fn a_treasury_account_is_an_ordinary_ed25519_account() {
        let t = Treasury::provision(2, 3).expect("provision");
        assert_eq!(
            t.account,
            crate::account::account_of(crate::account::Scheme::Ed25519, &t.group_key),
            "a treasury must be indistinguishable from a single-key account"
        );
    }

    #[test]
    fn two_ceremonies_never_produce_the_same_account() {
        let a = Treasury::provision(2, 3).expect("a");
        let b = Treasury::provision(2, 3).expect("b");
        assert_ne!(a.account, b.account, "each provisioning is a distinct treasury");
    }

    #[test]
    fn a_threshold_below_two_or_above_the_holders_is_refused() {
        assert!(Treasury::provision(1, 3).is_err(), "1-of-n is not a threshold");
        assert!(Treasury::provision(4, 3).is_err(), "more signers than holders can never sign");
    }
}

// ---------------------------------------------------------------- ceremony

use crate::ceremony::{Ceremony, Ed25519 as Suite};

/// One share per participant, for an Ed25519 vault.
pub type Id = IdentifierFor<Ed25519Suite>;
/// The keys one participant holds.
pub type Keys = ThresholdKeys<Ed25519Suite>;

/// Run the ceremony for an Ed25519 vault.
pub fn ceremony<R: rand_core::RngCore + rand_core::CryptoRng>(
    threshold: u16,
    participants: u16,
    rng: &mut R,
) -> Result<BTreeMap<Id, Keys>, CeremonyError> {
    Ceremony::new(threshold, participants)?.run_for::<Suite, R>(rng)
}

/// The vault's address: the group key itself. Nothing is derived — for an
/// ordinary Ed25519 account this *is* the account.
pub fn vault_address_of(public: &PublicKeyPackage<Ed25519Suite>) -> [u8; 32] {
    public
        .verifying_key()
        .serialize()
        .ok()
        .and_then(|v| v.try_into().ok())
        .expect("ed25519 keys are 32 bytes")
}

// ------------------------------------------------------- threshold signing

use crate::signing::{Aggregator, Ed25519Quorum, SigningError};

/// What can go wrong producing a vault signature.
#[derive(Debug)]
pub enum VaultError {
    Ceremony(CeremonyError),
    Signing(SigningError),
    /// The aggregated signature did not verify as ordinary ed25519. A share
    /// was wrong, and it is found here rather than by whoever would have
    /// rejected the transaction.
    DoesNotVerify,
}

/// Check an aggregated signature exactly as any ed25519 verifier will.
///
/// Called before a signature is used for anything, because a bad share is
/// cheap to find here and expensive to find anywhere else.
pub fn verify(vault: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Result<(), VaultError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(vault).map_err(|_| VaultError::DoesNotVerify)?;
    vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(sig))
        .map_err(|_| VaultError::DoesNotVerify)
}

/// Drive both rounds against a quorum that may sit on other machines.
///
/// The coordinator calling this holds no share: it sees nonce commitments and
/// signature shares, and neither reconstructs a key.
pub fn sign_with(
    quorum: &mut dyn Ed25519Quorum,
    threshold: u16,
    public: &PublicKeyPackage<Ed25519Suite>,
    message: &[u8],
    now: u64,
) -> Result<[u8; 64], VaultError> {
    // Fresh per attempt, so a retry after a timeout never collides with the
    // request whose nonces a custodian still holds.
    let request_id: u64 = rand::RngCore::next_u64(&mut rand::rngs::OsRng);
    let commitments = quorum.round1(request_id, message, now);
    let want = usize::from(threshold);
    if commitments.len() < want {
        return Err(VaultError::Signing(SigningError::BelowThreshold));
    }
    let mut coord: Aggregator<Suite> = Aggregator::new(message.to_vec(), threshold);
    let chosen: Vec<Id> = commitments.keys().copied().take(want).collect();
    for id in &chosen {
        coord.add_commitment(*id, commitments[id].clone());
    }
    let package = coord.package().map_err(VaultError::Signing)?;
    let shares = quorum.round2(request_id, &chosen, &package);
    if shares.len() < want {
        return Err(VaultError::Signing(SigningError::BelowThreshold));
    }
    let sig = coord
        .aggregate(&package, &shares, public)
        .map_err(VaultError::Signing)?;
    let bytes: [u8; 64] = sig
        .serialize()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(VaultError::DoesNotVerify)?;
    verify(&vault_address_of(public), message, &bytes)?;
    Ok(bytes)
}
