//! Producing a signature with a key nobody holds.
//!
//! Two rounds. Each participant first commits to nonces without revealing
//! them, then — once it knows the message and everyone else's commitments —
//! releases a share of the signature. A coordinator combines the shares into
//! one ordinary signature that verifies against the group key.
//!
//! The cryptography is `reddsa`'s FROST over RedPallas, unmodified. This is the
//! plain path, which is what signing an anchor needs. Spending from an Orchard
//! note additionally requires the signature to be *rerandomized* — the same
//! crate provides `frost::redpallas::rerandomized` for it, and the ceremony and
//! session below are unchanged either way. What this module adds is the
//! discipline around the rounds, and the discipline is where the money is
//! lost:
//!
//! - **A nonce is used once.** Signing twice from one commitment leaks the
//!   share, and enough leaked shares is the key. [`SigningSession`] consumes
//!   its nonces, so the type system refuses the second use rather than
//!   trusting an operator not to retry.
//! - **Everyone signs the same message.** A participant tricked into signing a
//!   different payload contributes a share of a signature over something
//!   nobody agreed to.
//! - **Below the threshold, nothing is produced.** Not a weak signature — no
//!   signature.

//!
//! Generic over the ciphersuite for the same reason the ceremony is: the
//! nonce-once and same-message disciplines are the part worth having exactly
//! one copy of. `Zcash` and `Ed25519` instantiate it; the type aliases keep the
//! Zcash call sites reading as they did.

use std::collections::BTreeMap;

use frost_core::Ciphersuite;

pub use crate::ceremony::{Identifier, IdentifierFor, Ed25519, ThresholdKeys, VaultKeys, Zcash};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SigningError {
    /// Fewer commitments or shares than the vault requires. No signature is
    /// produced — there is no such thing as a partial one.
    BelowThreshold,
    /// A share arrived from someone not in this round.
    UnexpectedSigner,
    /// A participant signed a different message from the rest.
    MessageMismatch,
    /// The library refused. Not something to work around.
    Crypto,
}

/// One participant's part in one signature.
///
/// Holds the nonces, and is consumed when they are used — so the type system,
/// not an operator's discipline, is what prevents the reuse that leaks a share.
pub struct Session<C: Ciphersuite> {
    id: IdentifierFor<C>,
    nonces: frost_core::round1::SigningNonces<C>,
    commitments: frost_core::round1::SigningCommitments<C>,
}

/// One Zcash participant's part in one signature.
pub type SigningSession = Session<Zcash>;

impl<C: Ciphersuite> Session<C> {
    /// Round one: commit to nonces without revealing them.
    pub fn begin<R: rand_core::RngCore + rand_core::CryptoRng>(
        id: IdentifierFor<C>,
        keys: &ThresholdKeys<C>,
        rng: &mut R,
    ) -> Session<C> {
        let (nonces, commitments) =
            frost_core::round1::commit(keys.key_package.signing_share(), rng);
        Session {
            id,
            nonces,
            commitments,
        }
    }

    pub fn id(&self) -> IdentifierFor<C> {
        self.id
    }

    pub fn commitments(&self) -> frost_core::round1::SigningCommitments<C> {
        self.commitments
    }

    /// Round two: release a share of the signature over `message`.
    ///
    /// Takes `self` by value. That is the whole nonce-reuse defence: there is
    /// no second call to make.
    /// The nonces this session committed to.
    ///
    /// `pub(crate)` so the re-randomized path can reach them without the
    /// by-value discipline in [`Self::sign`] being bypassed from outside.
    pub(crate) fn nonces(&self) -> &frost_core::round1::SigningNonces<C> {
        &self.nonces
    }

    pub fn sign(
        self,
        keys: &ThresholdKeys<C>,
        package: &frost_core::SigningPackage<C>,
    ) -> Result<frost_core::round2::SignatureShare<C>, SigningError> {
        frost_core::round2::sign(package, &self.nonces, &keys.key_package)
            .map_err(|_| SigningError::Crypto)
    }
}

/// Collects commitments and shares, and produces the signature.
///
/// A coordinator is untrusted by construction: it sees commitments, a message,
/// and shares, none of which reveal a key. The worst it can do is fail to
/// produce a signature.
pub struct Aggregator<C: Ciphersuite> {
    message: Vec<u8>,
    commitments: BTreeMap<IdentifierFor<C>, frost_core::round1::SigningCommitments<C>>,
    threshold: u16,
}

/// The Zcash coordinator.
pub type Coordinator = Aggregator<Zcash>;

impl<C: Ciphersuite> Aggregator<C> {
    pub fn new(message: Vec<u8>, threshold: u16) -> Aggregator<C> {
        Aggregator {
            message,
            commitments: BTreeMap::new(),
            threshold,
        }
    }

    pub fn add_commitment(
        &mut self,
        id: IdentifierFor<C>,
        c: frost_core::round1::SigningCommitments<C>,
    ) {
        self.commitments.insert(id, c);
    }

    pub fn ready(&self) -> bool {
        self.commitments.len() >= usize::from(self.threshold)
    }

    /// The package every participant signs. One package, so a participant that
    /// signs something else produces a share that does not combine.
    pub fn package(&self) -> Result<frost_core::SigningPackage<C>, SigningError> {
        if !self.ready() {
            return Err(SigningError::BelowThreshold);
        }
        Ok(frost_core::SigningPackage::new(
            self.commitments.clone(),
            &self.message,
        ))
    }

    /// Combine the shares into one signature.
    pub fn aggregate(
        &self,
        package: &frost_core::SigningPackage<C>,
        shares: &BTreeMap<IdentifierFor<C>, frost_core::round2::SignatureShare<C>>,
        public: &frost_core::keys::PublicKeyPackage<C>,
    ) -> Result<frost_core::Signature<C>, SigningError> {
        if shares.len() < usize::from(self.threshold) {
            return Err(SigningError::BelowThreshold);
        }
        for id in shares.keys() {
            if !self.commitments.contains_key(id) {
                return Err(SigningError::UnexpectedSigner);
            }
        }
        frost_core::aggregate(package, shares, public).map_err(|_| SigningError::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::Ceremony;
    use rand::rngs::OsRng;
    #[allow(unused_imports)]
    use reddsa::frost::redpallas as frost;

    /// A signature the whole group can verify, from shares no one of which is
    /// the key.
    #[test]
    fn a_threshold_of_signers_produces_one_valid_signature() {
        let vault = Ceremony::new(7, 10).unwrap().run(&mut OsRng).unwrap();
        let message = b"anchor id goes here".to_vec();

        // Seven of the ten take part.
        let signing: Vec<_> = vault.keys().copied().take(7).collect();
        let mut sessions = Vec::new();
        let mut coordinator = Coordinator::new(message.clone(), 7);
        for id in &signing {
            let s = SigningSession::begin(*id, &vault[id], &mut OsRng);
            coordinator.add_commitment(*id, s.commitments());
            sessions.push(s);
        }
        assert!(coordinator.ready());

        let package = coordinator.package().unwrap();
        let mut shares = BTreeMap::new();
        for s in sessions {
            let id = s.id();
            shares.insert(id, s.sign(&vault[&id], &package).unwrap());
        }

        let public = &vault[&signing[0]].public_package;
        let sig = coordinator.aggregate(&package, &shares, public).unwrap();

        // It verifies against the group key — an ordinary Schnorr signature,
        // indistinguishable from one made by a single holder of a key that no
        // single holder has.
        assert!(
            public.verifying_key().verify(&message, &sig).is_ok(),
            "the group signature did not verify"
        );
    }

    /// Six of ten produces nothing. Not a weaker signature — no signature.
    #[test]
    fn below_the_threshold_no_signature_exists() {
        let vault = Ceremony::new(7, 10).unwrap().run(&mut OsRng).unwrap();
        let mut coordinator = Coordinator::new(b"anchor".to_vec(), 7);
        for id in vault.keys().copied().take(6) {
            let s = SigningSession::begin(id, &vault[&id], &mut OsRng);
            coordinator.add_commitment(id, s.commitments());
        }
        assert!(!coordinator.ready());
        assert!(matches!(
            coordinator.package(),
            Err(SigningError::BelowThreshold)
        ));
    }

    /// Someone who never committed to a round cannot produce a share for it at
    /// all — the refusal happens in the signing step, before a coordinator gets
    /// the chance to notice.
    ///
    /// Stronger than the check `Coordinator::aggregate` makes, and worth
    /// knowing which line actually holds: a coordinator that forgot to check
    /// membership would still not be able to admit an outsider here.
    #[test]
    fn an_outsider_cannot_produce_a_share_for_a_round_they_missed() {
        let vault = Ceremony::new(2, 3).unwrap().run(&mut OsRng).unwrap();
        let ids: Vec<_> = vault.keys().copied().collect();

        let mut coordinator = Coordinator::new(b"anchor".to_vec(), 2);
        for id in ids.iter().take(2) {
            let s = SigningSession::begin(*id, &vault[id], &mut OsRng);
            coordinator.add_commitment(*id, s.commitments());
        }
        let package = coordinator.package().unwrap();

        let outsider = ids[2];
        let stray = SigningSession::begin(outsider, &vault[&outsider], &mut OsRng);
        assert!(
            matches!(
                stray.sign(&vault[&outsider], &package),
                Err(SigningError::Crypto)
            ),
            "an outsider produced a share for a round they never joined"
        );
    }

    /// And the coordinator refuses one anyway, so the guarantee does not rest
    /// on the library alone.
    #[test]
    fn the_coordinator_refuses_a_share_it_did_not_ask_for() {
        let vault = Ceremony::new(2, 3).unwrap().run(&mut OsRng).unwrap();
        let ids: Vec<_> = vault.keys().copied().collect();

        // A full, valid round between the first two.
        let mut coordinator = Coordinator::new(b"anchor".to_vec(), 2);
        let mut sessions = Vec::new();
        for id in ids.iter().take(2) {
            let s = SigningSession::begin(*id, &vault[id], &mut OsRng);
            coordinator.add_commitment(*id, s.commitments());
            sessions.push(s);
        }
        let package = coordinator.package().unwrap();
        let mut shares = BTreeMap::new();
        for s in sessions {
            let id = s.id();
            shares.insert(id, s.sign(&vault[&id], &package).unwrap());
        }
        // A third entry appears under an identifier the coordinator never
        // solicited, reusing a valid share's bytes.
        let borrowed = *shares.values().next().unwrap();
        shares.insert(ids[2], borrowed);

        let public = &vault[&ids[0]].public_package;
        assert!(matches!(
            coordinator.aggregate(&package, &shares, public),
            Err(SigningError::UnexpectedSigner)
        ));
    }

    /// A signature over one message does not verify against another.
    #[test]
    fn a_signature_is_bound_to_its_message() {
        let vault = Ceremony::new(2, 3).unwrap().run(&mut OsRng).unwrap();
        let ids: Vec<_> = vault.keys().copied().take(2).collect();
        let message = b"anchor A".to_vec();

        let mut coordinator = Coordinator::new(message.clone(), 2);
        let mut sessions = Vec::new();
        for id in &ids {
            let s = SigningSession::begin(*id, &vault[id], &mut OsRng);
            coordinator.add_commitment(*id, s.commitments());
            sessions.push(s);
        }
        let package = coordinator.package().unwrap();
        let mut shares = BTreeMap::new();
        for s in sessions {
            let id = s.id();
            shares.insert(id, s.sign(&vault[&id], &package).unwrap());
        }
        let public = &vault[&ids[0]].public_package;
        let sig = coordinator.aggregate(&package, &shares, public).unwrap();

        assert!(public.verifying_key().verify(&message, &sig).is_ok());
        assert!(
            public.verifying_key().verify(b"anchor B", &sig).is_err(),
            "a signature was portable"
        );
    }
}

// --- Signing an Orchard spend ---

/// Threshold signing with a **re-randomized** key, which is the only kind
/// Orchard accepts.
///
/// # Why the ordinary path is not enough
///
/// An Orchard action is authorised under `rk = ak + alpha·G`, not under `ak`.
/// Each action carries its own randomizer `alpha`, so a signature produced by
/// plain FROST verifies under the group key and is rejected by the bundle — the
/// ceremony would look correct, produce a valid signature, and be unable to
/// spend anything.
///
/// That is not a detail of Orchard's implementation. Re-randomization is what
/// stops an observer linking two spends by the key that authorised them, which
/// is a privacy property rather than a cryptographic convenience, and it is why
/// `reddsa` ships a separate `rerandomized` module at all.
///
/// # Where the randomizer comes from
///
/// Not from here. The **builder** of the bundle chooses each `alpha`, and a
/// signer learns it from the PCZT it is asked to sign (`spend.alpha()`). The
/// coordinator distributes the seed; every signer must use the same one or the
/// shares will not aggregate.
/// A set of share-holders a coordinator drives through the two rounds, without
/// caring whether they are in this process or across a network. The
/// coordinator holds no share: it sends a sighash and the actions' randomizers
/// out, and gets commitments and shares back.
pub trait Quorum {
    /// Round one: every reachable participant commits to one nonce per action.
    /// Keyed by identifier; a participant that does not answer is simply
    /// absent, and the coordinator proceeds if enough did.
    fn round1(
        &mut self,
        request_id: u64,
        sighash: [u8; 32],
        alphas: &[orchard::Randomizer<orchard::PallasBlake2b512>],
        now: u64,
    ) -> BTreeMap<Identifier, Vec<frost_core::round1::SigningCommitments<Zcash>>>;

    /// Round two: the chosen participants sign each action's package. Only the
    /// `chosen` set is asked — the coordinator has already picked a threshold
    /// from round one's answers and built the packages from exactly them.
    fn round2(
        &mut self,
        request_id: u64,
        chosen: &[Identifier],
        packages: &[frost_core::SigningPackage<Zcash>],
    ) -> BTreeMap<Identifier, Vec<frost_core::round2::SignatureShare<Zcash>>>;
}

/// The share-holders in this process: the V0 posture, and what every test
/// drives. Holds the shares; a `RemoteQuorum` holds only addresses.
pub struct LocalQuorum {
    participants: Vec<crate::custodian::Participant>,
}

impl LocalQuorum {
    pub fn new(keys: Vec<VaultKeys>) -> LocalQuorum {
        LocalQuorum {
            participants: keys
                .into_iter()
                .map(crate::custodian::Participant::new)
                .collect(),
        }
    }
}

impl Quorum for LocalQuorum {
    fn round1(
        &mut self,
        request_id: u64,
        sighash: [u8; 32],
        alphas: &[orchard::Randomizer<orchard::PallasBlake2b512>],
        now: u64,
    ) -> BTreeMap<Identifier, Vec<frost_core::round1::SigningCommitments<Zcash>>> {
        let mut out = BTreeMap::new();
        for p in &mut self.participants {
            if let Ok(c) = p.round1(
                request_id,
                sighash,
                alphas.to_vec(),
                now,
                &mut rand::rngs::OsRng,
            ) {
                out.insert(p.id(), c);
            }
        }
        out
    }

    fn round2(
        &mut self,
        request_id: u64,
        chosen: &[Identifier],
        packages: &[frost_core::SigningPackage<Zcash>],
    ) -> BTreeMap<Identifier, Vec<frost_core::round2::SignatureShare<Zcash>>> {
        let mut out = BTreeMap::new();
        for p in &mut self.participants {
            if chosen.contains(&p.id()) {
                if let Ok(shares) = p.round2(request_id, packages) {
                    out.insert(p.id(), shares);
                }
            }
        }
        out
    }
}

/// The Ed25519 counterpart of [`Quorum`]: one message, one signature, no
/// randomizers. Same two rounds, same discipline.
pub trait Ed25519Quorum {
    fn round1(
        &mut self,
        request_id: u64,
        message: &[u8],
        now: u64,
    ) -> BTreeMap<IdentifierFor<Ed25519>, frost_core::round1::SigningCommitments<Ed25519>>;

    fn round2(
        &mut self,
        request_id: u64,
        chosen: &[IdentifierFor<Ed25519>],
        package: &frost_core::SigningPackage<Ed25519>,
    ) -> BTreeMap<IdentifierFor<Ed25519>, frost_core::round2::SignatureShare<Ed25519>>;
}

/// Ed25519 share-holders in this process: the V0 posture and the tests.
pub struct LocalEd25519Quorum {
    participants: Vec<crate::custodian::ed25519::Participant>,
}

impl LocalEd25519Quorum {
    pub fn new(keys: Vec<ThresholdKeys<Ed25519>>) -> LocalEd25519Quorum {
        LocalEd25519Quorum {
            participants: keys
                .into_iter()
                .map(crate::custodian::ed25519::Participant::new)
                .collect(),
        }
    }
}

impl Ed25519Quorum for LocalEd25519Quorum {
    fn round1(
        &mut self,
        request_id: u64,
        message: &[u8],
        now: u64,
    ) -> BTreeMap<IdentifierFor<Ed25519>, frost_core::round1::SigningCommitments<Ed25519>> {
        let mut out = BTreeMap::new();
        for p in &mut self.participants {
            if let Ok(c) = p.round1(request_id, message.to_vec(), now, &mut rand::rngs::OsRng) {
                out.insert(p.id(), c);
            }
        }
        out
    }

    fn round2(
        &mut self,
        request_id: u64,
        chosen: &[IdentifierFor<Ed25519>],
        package: &frost_core::SigningPackage<Ed25519>,
    ) -> BTreeMap<IdentifierFor<Ed25519>, frost_core::round2::SignatureShare<Ed25519>> {
        let mut out = BTreeMap::new();
        for p in &mut self.participants {
            if chosen.contains(&p.id()) {
                if let Ok(s) = p.round2(request_id, package) {
                    out.insert(p.id(), s);
                }
            }
        }
        out
    }
}

pub mod orchard {
    use super::*;
    #[allow(unused_imports)]
    use reddsa::frost::redpallas as frost;

    pub use frost_rerandomized::{RandomizedParams, Randomizer};
    pub use reddsa::frost::redpallas::PallasBlake2b512;

    /// The parameters for one action, from the `alpha` its bundle chose.
    ///
    /// `alpha` comes from the PCZT the signers are asked to authorise
    /// (`spend.alpha()`), never from here. A signer that generated its own
    /// randomizer would produce a signature under a key the bundle's `rk` does
    /// not match, and `apply_signature` would reject it — which is the right
    /// failure, but it is better not to reach for it.
    pub fn params_for(
        group_key: &frost::VerifyingKey,
        alpha: Randomizer<PallasBlake2b512>,
    ) -> RandomizedParams<PallasBlake2b512> {
        RandomizedParams::from_randomizer(group_key, alpha)
    }

    /// One signer's share, under the action's randomizer.
    ///
    /// Consumes the session by value for the same reason [`SigningSession::sign`]
    /// does: a nonce used twice leaks the share, and a session that cannot be
    /// used twice cannot leak it.
    pub fn sign_share(
        session: SigningSession,
        keys: &VaultKeys,
        package: &frost::SigningPackage,
        alpha: Randomizer<PallasBlake2b512>,
    ) -> Result<frost::round2::SignatureShare, SigningError> {
        // `frost_rerandomized::sign` is deprecated in favour of deriving the
        // randomizer from the signing commitments, so that participants need
        // not trust a coordinator's choice of it. That advice does not apply
        // here and cannot: Orchard's builder fixes `alpha` when it builds the
        // action, the bundle's `rk` is derived from it, and a randomizer
        // derived from FROST commitments would authorise nothing.
        //
        // The trust the deprecation is about is recovered elsewhere — a signer
        // receives `alpha` inside the PCZT it is asked to authorise, alongside
        // the `rk` it must match, and can check the two agree before signing.
        #[allow(deprecated)]
        frost_rerandomized::sign(package, session.nonces(), &keys.key_package, alpha)
            .map_err(|_| SigningError::Crypto)
    }

    /// Re-type a FROST signature as the spend authorisation an action takes.
    ///
    /// The bytes are already right — `reddsa`'s FROST is RedPallas precisely so
    /// they would be — but the two crates name the type differently, and
    /// nothing should paper over that with a transmute. Serialising and
    /// re-reading costs nothing and fails loudly if the formats ever diverge.
    pub fn to_spend_auth(
        sig: &frost::Signature,
    ) -> Result<
        ::orchard::primitives::redpallas::Signature<::orchard::primitives::redpallas::SpendAuth>,
        SigningError,
    > {
        let bytes: [u8; 64] = sig
            .serialize()
            .map_err(|_| SigningError::Crypto)?
            .try_into()
            .map_err(|_| SigningError::Crypto)?;
        Ok(bytes.into())
    }

    /// Combine shares into the signature an Orchard action will accept.
    ///
    /// The parameters must carry the same `alpha` the shares were produced
    /// under and the bundle's `rk` was derived from. Aggregation fails
    /// otherwise rather than producing a signature that verifies against
    /// nothing.
    pub fn aggregate(
        package: &frost::SigningPackage,
        shares: &std::collections::BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
        pubkeys: &frost::keys::PublicKeyPackage,
        params: &RandomizedParams<PallasBlake2b512>,
    ) -> Result<frost::Signature, SigningError> {
        frost_rerandomized::aggregate(package, shares, pubkeys, params)
            .map_err(|_| SigningError::Crypto)
    }
}

#[cfg(test)]
mod orchard_signing_tests {
    //! The integration risk, isolated.
    //!
    //! An Orchard action is authorised under `rk = ak + alpha·G`. These prove
    //! the ceremony produces a signature that verifies under exactly that key
    //! — which is the check `orchard::pczt::Action::apply_signature` makes
    //! before accepting one, so passing here is passing there.
    #[allow(unused_imports)]
    use reddsa::frost::redpallas as frost;

    use super::orchard::{aggregate, params_for, sign_share, Randomizer};
    use super::*;
    use crate::ceremony::Ceremony;
    use reddsa::frost::redpallas::PallasBlake2b512;
    use std::collections::BTreeMap;

    fn vault(threshold: u16, n: u16) -> Vec<(Identifier, VaultKeys)> {
        Ceremony::new(threshold, n)
            .expect("a valid threshold")
            .run(&mut rand::rngs::OsRng)
            .expect("the ceremony must complete")
            .into_iter()
            .collect()
    }

    /// An `alpha` of the kind a bundle hands us.
    ///
    /// A free scalar, not one derived from the signing package — because
    /// Orchard's builder chooses it and a signer only ever receives it. Small
    /// distinct values here; a real one is random and never reused, since a
    /// repeated randomizer links two spends.
    fn alpha(n: u8) -> Randomizer<PallasBlake2b512> {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Randomizer::deserialize(&bytes).expect("a small scalar is a valid randomizer")
    }

    fn threshold_sign(
        keys: &[(Identifier, VaultKeys)],
        threshold: usize,
        sighash: &[u8],
        a: Randomizer<PallasBlake2b512>,
    ) -> frost::Signature {
        let mut rng = rand::rngs::OsRng;
        let sessions: Vec<SigningSession> = keys
            .iter()
            .take(threshold)
            .map(|(id, k)| SigningSession::begin(*id, k, &mut rng))
            .collect();

        let mut coord = Coordinator::new(sighash.to_owned(), threshold as u16);
        for s in &sessions {
            coord.add_commitment(s.id(), s.commitments());
        }
        let package = coord.package().expect("a signing package");

        let mut shares = BTreeMap::new();
        for (s, (_, k)) in sessions.into_iter().zip(keys.iter()) {
            let id = s.id();
            shares.insert(id, sign_share(s, k, &package, a).expect("a share"));
        }
        let params = params_for(keys[0].1.public_package.verifying_key(), a);
        aggregate(&package, &shares, &keys[0].1.public_package, &params).expect("aggregation")
    }

    /// The headline: a threshold of signers authorises a spend randomized by
    /// the bundle's own `alpha`.
    #[test]
    fn the_vault_can_authorise_a_randomized_spend() {
        let keys = vault(2, 3);
        let sighash = [0x42u8; 32];
        let a = alpha(11);
        let sig = threshold_sign(&keys, 2, &sighash, a);

        // Exactly the check `apply_signature` makes: against the *randomized*
        // key, never the group key.
        let params = params_for(keys[0].1.public_package.verifying_key(), a);
        assert!(
            params
                .randomized_verifying_key()
                .verify(&sighash, &sig)
                .is_ok(),
            "the vault produced a signature Orchard would reject"
        );
    }

    /// And it does not verify under the group key — which is what a plain
    /// FROST ceremony would have produced, and why this module exists.
    #[test]
    fn the_group_key_does_not_verify_it() {
        let keys = vault(2, 3);
        let sighash = [0x42u8; 32];
        let sig = threshold_sign(&keys, 2, &sighash, alpha(11));
        assert!(
            keys[0].1.group_key().verify(&sighash, &sig).is_err(),
            "a randomized signature verified under the group key"
        );
    }

    /// A different action means a different `alpha`, and a signature does not
    /// carry between them. Reuse would link two spends, which is the property
    /// re-randomization exists to prevent.
    #[test]
    fn a_signature_does_not_carry_to_another_action() {
        let keys = vault(2, 3);
        let sighash = [7u8; 32];
        let sig = threshold_sign(&keys, 2, &sighash, alpha(11));
        let other = params_for(keys[0].1.public_package.verifying_key(), alpha(12));
        assert!(
            other
                .randomized_verifying_key()
                .verify(&sighash, &sig)
                .is_err(),
            "one action's signature authorised another"
        );
    }

    /// Nor to another sighash — a signature authorises one transaction.
    #[test]
    fn a_signature_does_not_carry_to_another_transaction() {
        let keys = vault(2, 3);
        let a = alpha(13);
        let sig = threshold_sign(&keys, 2, &[1u8; 32], a);
        let params = params_for(keys[0].1.public_package.verifying_key(), a);
        assert!(params
            .randomized_verifying_key()
            .verify(&[2u8; 32], &sig)
            .is_err());
    }

    /// Below the threshold there is no signature, not a weaker one.
    #[test]
    fn one_signer_short_produces_nothing() {
        let keys = vault(3, 5);
        let mut rng = rand::rngs::OsRng;
        let sessions: Vec<SigningSession> = keys
            .iter()
            .take(2) // one short of three
            .map(|(id, k)| SigningSession::begin(*id, k, &mut rng))
            .collect();
        let mut coord = Coordinator::new(vec![1, 2, 3], 3);
        for s in &sessions {
            coord.add_commitment(s.id(), s.commitments());
        }
        assert!(
            !coord.ready(),
            "a coordinator accepted less than the threshold"
        );
        assert!(matches!(coord.package(), Err(SigningError::BelowThreshold)));
    }
}
