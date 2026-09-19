//! The signer ceremony: bringing a vault key into existence without ever
//! assembling it.
//!
//! Distributed key generation. Each participant ends up holding a share of a
//! key that **no one ever holds whole** — not during generation, not after, not
//! on any one machine at any moment. That is the property that makes a
//! threshold vault different from a multisig wallet with a backup somewhere.
//!
//! The cryptography is `reddsa`'s FROST over RedPallas — the Zcash Foundation's
//! implementation of the signature scheme Orchard spend authorization uses.
//! **None of it is reimplemented here.** Threshold key generation fails
//! silently and totally when it is got wrong, and a hand-rolled version that
//! passes its own tests is exactly what that failure looks like.
//!
//! What this module adds is the part around it: running the rounds in order,
//! refusing a threshold that is not a real majority, and confirming that every
//! participant derived the *same* group key — which is the check that catches a
//! participant who was fed different packages from the others.

//!
//! # One driver, three curves
//!
//! Zcash signs under RedPallas, Ed25519 under ed25519, and a Taproot vault would
//! sign under secp256k1. All three are `frost-core` ciphersuites, so the rounds
//! below are written once over [`Ciphersuite`] and instantiated per chain.
//! That is not a convenience: a second hand-written DKG driver for a second
//! curve would be a second place for the round-ordering bugs this file exists
//! to prevent.

use std::collections::BTreeMap;

use frost_core::keys::dkg;
use frost_core::Ciphersuite;
use reddsa::frost::redpallas::PallasBlake2b512;

/// The Zcash ciphersuite: RedPallas, as Orchard spend authorization uses.
pub type Zcash = PallasBlake2b512;
/// The Ed25519 ciphersuite: plain ed25519. Not rerandomized — Ed25519 verifies an
/// ordinary ed25519 signature against the account's key.
pub type Ed25519 = frost_ed25519::Ed25519Sha512;

/// A participant's identity within a ceremony, for any suite.
pub type IdentifierFor<C> = frost_core::Identifier<C>;
/// A participant's identity within the Zcash ceremony.
pub type Identifier = IdentifierFor<Zcash>;

/// What a participant walks away with.
///
/// The share never leaves the machine that generated it. The public package is
/// what everyone needs to verify signatures afterwards, and is safe to publish.
#[derive(Clone)]
pub struct ThresholdKeys<C: Ciphersuite> {
    pub key_package: frost_core::keys::KeyPackage<C>,
    pub public_package: frost_core::keys::PublicKeyPackage<C>,
}

impl<C: Ciphersuite> ThresholdKeys<C> {
    /// The group's verifying key — the vault's public identity.
    pub fn group_key(&self) -> frost_core::VerifyingKey<C> {
        *self.public_package.verifying_key()
    }
}

/// The Zcash vault's shares.
pub type VaultKeys = ThresholdKeys<Zcash>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CeremonyError {
    /// A threshold at or below half the participants lets two disjoint quorums
    /// sign conflicting things, and both would verify.
    ThresholdNotAMajority,
    /// Fewer than two participants is not a threshold scheme.
    TooFewParticipants,
    /// A round was run out of order, or a participant is missing.
    Incomplete,
    /// Participants did not agree on the group key. Someone was fed different
    /// packages from everyone else, and continuing would produce a vault only
    /// some of them can sign for.
    DisagreedOnGroupKey,
    /// The library refused a package. Not something to work around.
    Crypto,
}

/// Run a distributed key generation.
///
/// Written as a single driver rather than a network protocol on purpose: the
/// rounds and their ordering are what is easy to get wrong, and a real
/// deployment runs the same sequence with the message-passing in between. The
/// per-participant state is exactly what would be held on separate machines.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ceremony {
    threshold: u16,
    participants: u16,
}

impl Ceremony {
    /// A `threshold`-of-`participants` vault. The plan's candidate is 7 of 10.
    pub fn new(threshold: u16, participants: u16) -> Result<Ceremony, CeremonyError> {
        if participants < 2 {
            return Err(CeremonyError::TooFewParticipants);
        }
        if threshold == 0 || threshold > participants {
            return Err(CeremonyError::ThresholdNotAMajority);
        }
        // Strictly more than half. At exactly half, two disjoint quorums exist.
        if u32::from(threshold) * 2 <= u32::from(participants) {
            return Err(CeremonyError::ThresholdNotAMajority);
        }
        Ok(Ceremony {
            threshold,
            participants,
        })
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }
    pub fn participants(&self) -> u16 {
        self.participants
    }

    /// Run all three rounds for the Zcash vault.
    pub fn run<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<BTreeMap<Identifier, VaultKeys>, CeremonyError> {
        self.run_for::<Zcash, R>(rng)
    }

    /// Run all three rounds and return each participant's keys, for any suite.
    ///
    /// The secret is never materialised: it exists only as the shares this
    /// returns, and only on the machines that generated them. In a real
    /// ceremony the loops below are separate machines and the maps are the
    /// messages between them.
    pub fn run_for<C: Ciphersuite, R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<BTreeMap<IdentifierFor<C>, ThresholdKeys<C>>, CeremonyError> {
        let ids: Vec<IdentifierFor<C>> = (1..=self.participants)
            .map(|i| IdentifierFor::<C>::try_from(i).map_err(|_| CeremonyError::Crypto))
            .collect::<Result<_, _>>()?;

        // Round 1: each participant commits to a polynomial and broadcasts.
        let mut r1_secret = BTreeMap::new();
        let mut r1_public = BTreeMap::new();
        for id in &ids {
            let (secret, package) = dkg::part1(*id, self.participants, self.threshold, &mut *rng)
                .map_err(|_| CeremonyError::Crypto)?;
            r1_secret.insert(*id, secret);
            r1_public.insert(*id, package);
        }

        // Round 2: each participant answers every other, privately.
        let mut r2_secret = BTreeMap::new();
        let mut r2_public: BTreeMap<
            IdentifierFor<C>,
            BTreeMap<IdentifierFor<C>, dkg::round2::Package<C>>,
        > = BTreeMap::new();
        for id in &ids {
            let others: BTreeMap<_, _> = r1_public
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let secret = r1_secret.remove(id).ok_or(CeremonyError::Incomplete)?;
            let (s2, p2) = dkg::part2(secret, &others).map_err(|_| CeremonyError::Crypto)?;
            r2_secret.insert(*id, s2);
            r2_public.insert(*id, p2);
        }

        // Round 3: each participant assembles its share.
        let mut out = BTreeMap::new();
        for id in &ids {
            let r1_from_others: BTreeMap<_, _> = r1_public
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            // The round-2 packages addressed to *this* participant.
            let mut r2_for_me = BTreeMap::new();
            for (from, packages) in &r2_public {
                if from == id {
                    continue;
                }
                let p = packages.get(id).ok_or(CeremonyError::Incomplete)?;
                r2_for_me.insert(*from, p.clone());
            }
            let secret = r2_secret.remove(id).ok_or(CeremonyError::Incomplete)?;
            let (key_package, public_package) = dkg::part3(&secret, &r1_from_others, &r2_for_me)
                .map_err(|_| CeremonyError::Crypto)?;
            out.insert(
                *id,
                ThresholdKeys {
                    key_package,
                    public_package,
                },
            );
        }

        // Every participant must have derived the same vault. Disagreement
        // means someone was fed different packages, and the result would be a
        // vault only part of the group can sign for — which is a loss of funds
        // discovered at the worst possible moment.
        let mut keys = out.values().map(|k| k.group_key());
        let first = keys.next().ok_or(CeremonyError::Incomplete)?;
        if !keys.all(|k| k == first) {
            return Err(CeremonyError::DisagreedOnGroupKey);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn a_seven_of_ten_vault_comes_out_of_the_ceremony() {
        let c = Ceremony::new(7, 10).unwrap();
        let keys = c.run(&mut OsRng).expect("ceremony");
        assert_eq!(keys.len(), 10);

        // One vault, agreed by everyone — and no participant ever held it whole.
        let group = keys.values().next().unwrap().group_key();
        assert!(keys.values().all(|k| k.group_key() == group));
    }

    /// A threshold at or below half lets two disjoint quorums sign conflicting
    /// things, and both would verify.
    #[test]
    fn a_threshold_must_be_a_real_majority() {
        assert_eq!(
            Ceremony::new(5, 10).unwrap_err(),
            CeremonyError::ThresholdNotAMajority
        );
        assert_eq!(
            Ceremony::new(0, 10).unwrap_err(),
            CeremonyError::ThresholdNotAMajority
        );
        assert_eq!(
            Ceremony::new(11, 10).unwrap_err(),
            CeremonyError::ThresholdNotAMajority
        );
        assert_eq!(
            Ceremony::new(1, 1).unwrap_err(),
            CeremonyError::TooFewParticipants
        );
        assert!(Ceremony::new(6, 10).is_ok());
        assert!(Ceremony::new(2, 3).is_ok());
    }

    /// Two ceremonies produce two different vaults. Obvious, and worth pinning:
    /// a ceremony that produced a deterministic key would be a ceremony whose
    /// output an attacker could predict before it ran.
    #[test]
    fn each_ceremony_produces_its_own_vault() {
        let c = Ceremony::new(2, 3).unwrap();
        let a = c.run(&mut OsRng).unwrap();
        let b = c.run(&mut OsRng).unwrap();
        let ka = a.values().next().unwrap().group_key();
        let kb = b.values().next().unwrap().group_key();
        assert_ne!(ka, kb, "two ceremonies produced the same vault key");
    }
}

/// The vault's Orchard identity, built on the key the ceremony produced.
///
/// An Orchard full viewing key is `ak ‖ nk ‖ rivk`, 96 bytes. Only `ak` — the
/// spend *validating* key — corresponds to something the DKG makes: it is the
/// group verifying key, and the threshold signs under it.
///
/// `nk` and `rivk` are not the ceremony's to produce and never were (see
/// `DECISIONS` §13a). They grant **viewing**, never spending, so every signer
/// and the watcher may hold them — but they must be generated once,
/// deliberately, and distributed with the shares. A signer set that ran a DKG
/// and stopped owns a key that can authorise a spend and no way to find
/// anything to spend.
///
/// This is the function that makes the vault's address *be* the threshold key.
/// Without it the two are unrelated: notes arrive at an address nobody can
/// authorise, and the failure is silent until the first withdrawal.
pub fn orchard_viewing_key(
    group_key: &reddsa::frost::redpallas::VerifyingKey,
    nk: [u8; 32],
    rivk: [u8; 32],
) -> Option<orchard::keys::FullViewingKey> {
    let ak: [u8; 32] = group_key.serialize().ok()?.try_into().ok()?;
    let mut bytes = [0u8; 96];
    bytes[..32].copy_from_slice(&ak);
    bytes[32..64].copy_from_slice(&nk);
    bytes[64..].copy_from_slice(&rivk);
    orchard::keys::FullViewingKey::from_bytes(&bytes)
}

#[cfg(test)]
mod orchard_identity_tests {
    use super::*;

    #[test]
    fn the_vaults_address_is_the_threshold_key() {
        let keys = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap();
        let group = keys.values().next().unwrap().group_key();

        // `nk` and `rivk` are chosen, not derived. Not every pair is valid —
        // `rivk` must be a scalar the commitment accepts — so construction
        // returns an Option rather than pretending.
        let fvk = (0u8..64)
            .find_map(|n| orchard_viewing_key(&group, [n; 32], [n; 32]))
            .expect("some (nk, rivk) must be valid");

        // Every signer derives the same vault, because they share one group
        // key. A vault whose address depended on which signer you asked would
        // not be a vault.
        for k in keys.values() {
            let theirs = (0u8..64)
                .find_map(|n| orchard_viewing_key(&k.group_key(), [n; 32], [n; 32]))
                .unwrap();
            assert_eq!(
                theirs.address_at(0u32, orchard::keys::Scope::External),
                fvk.address_at(0u32, orchard::keys::Scope::External),
                "two signers derived different vault addresses"
            );
        }

        // And a different ceremony is a different vault.
        let other = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap();
        let other_group = other.values().next().unwrap().group_key();
        let other_fvk = (0u8..64)
            .find_map(|n| orchard_viewing_key(&other_group, [n; 32], [n; 32]))
            .unwrap();
        assert_ne!(
            other_fvk.address_at(0u32, orchard::keys::Scope::External),
            fvk.address_at(0u32, orchard::keys::Scope::External)
        );
    }
}
