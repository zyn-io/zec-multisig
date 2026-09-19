//! One share-holder's part in a distributed signature.
//!
//! A [`Participant`] holds exactly one FROST share and answers the two rounds
//! a coordinator drives — round one commits to nonces, round two releases a
//! share. It is the same work [`crate::signing::Session`] does, wrapped so it
//! can live behind a socket ([`crate::bin`] `zyn-custodian`) or be driven in
//! process ([`crate::signing::LocalQuorum`]). Either way the share never
//! leaves the machine: commitments and signature shares cross the boundary,
//! and neither reveals a key.
//!
//! # The one discipline
//!
//! A nonce is committed once and signed once. A request that is already live
//! cannot be re-opened (round one refuses it), and a session is consumed by
//! signing (round two drops the request). Requests live only in memory, so a
//! restart forgets them — which is the safe direction: a lost signing attempt
//! is nothing, a reused nonce is the share. Each request also carries a
//! deadline, so an abandoned coordinator cannot pin a share's nonces forever.

use std::collections::BTreeMap;

use frost_rerandomized::Randomizer;
use reddsa::frost::redpallas::PallasBlake2b512;

use crate::ceremony::{Identifier, VaultKeys};
use crate::signing::orchard::sign_share;
use crate::signing::{SigningError, SigningSession};

/// How long an opened request may wait for round two before its nonces are
/// released. Signing is seconds; this is generous and still bounded.
pub const REQUEST_TTL_SECS: u64 = 300;

struct Live {
    sighash: [u8; 32],
    alphas: Vec<Randomizer<PallasBlake2b512>>,
    /// One session per action, taken as each is signed.
    sessions: Vec<Option<SigningSession>>,
    opened_at: u64,
}

/// A single share, and the requests it has open.
pub struct Participant {
    keys: VaultKeys,
    live: BTreeMap<u64, Live>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CustodyError {
    /// A request id already has nonces committed. Re-opening it would risk
    /// signing twice under one nonce.
    AlreadyOpen,
    /// No such request — expired, never opened, or already signed. The
    /// coordinator retries the whole payout with fresh nonces.
    NoSuchRequest,
    /// Round two was given a different number of packages than round one had
    /// actions.
    ShapeMismatch,
    /// Round two asked for a signature over something other than what round
    /// one committed to. A coordinator that swapped the message under a
    /// committed nonce is either broken or attacking; either way, refuse.
    WrongMessage,
    Crypto,
}

impl From<SigningError> for CustodyError {
    fn from(_: SigningError) -> Self {
        CustodyError::Crypto
    }
}

impl Participant {
    pub fn new(keys: VaultKeys) -> Participant {
        Participant {
            keys,
            live: BTreeMap::new(),
        }
    }

    pub fn id(&self) -> Identifier {
        // The identifier is fixed at the ceremony and stored with the share.
        *self.keys.key_package.identifier()
    }

    /// Round one: commit to one nonce per action. Refuses a live request id.
    pub fn round1<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        request_id: u64,
        sighash: [u8; 32],
        alphas: Vec<Randomizer<PallasBlake2b512>>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<frost_core::round1::SigningCommitments<crate::ceremony::Zcash>>, CustodyError>
    {
        self.drop_expired(now);
        if self.live.contains_key(&request_id) {
            return Err(CustodyError::AlreadyOpen);
        }
        let id = self.id();
        let mut sessions = Vec::with_capacity(alphas.len());
        let mut commitments = Vec::with_capacity(alphas.len());
        for _ in &alphas {
            let s = SigningSession::begin(id, &self.keys, rng);
            commitments.push(s.commitments());
            sessions.push(Some(s));
        }
        self.live.insert(
            request_id,
            Live {
                sighash,
                alphas,
                sessions,
                opened_at: now,
            },
        );
        Ok(commitments)
    }

    /// Round two: sign each action's package with the nonce it committed to,
    /// under that action's randomizer. Consumes the request.
    pub fn round2(
        &mut self,
        request_id: u64,
        packages: &[frost_core::SigningPackage<crate::ceremony::Zcash>],
    ) -> Result<Vec<frost_core::round2::SignatureShare<crate::ceremony::Zcash>>, CustodyError> {
        let mut req = self
            .live
            .remove(&request_id)
            .ok_or(CustodyError::NoSuchRequest)?;
        if packages.len() != req.sessions.len() {
            return Err(CustodyError::ShapeMismatch);
        }
        if packages
            .iter()
            .any(|p| p.message().as_slice() != req.sighash.as_slice())
        {
            return Err(CustodyError::WrongMessage);
        }
        let mut shares = Vec::with_capacity(packages.len());
        for (i, package) in packages.iter().enumerate() {
            let session = req.sessions[i].take().ok_or(CustodyError::NoSuchRequest)?;
            shares.push(sign_share(session, &self.keys, package, req.alphas[i])?);
        }
        Ok(shares)
    }

    /// Forget requests whose round two never came. Their nonces are released
    /// unused; the coordinator retries with fresh ones.
    pub fn drop_expired(&mut self, now: u64) {
        self.live
            .retain(|_, r| now.saturating_sub(r.opened_at) < REQUEST_TTL_SECS);
    }

    pub fn open_requests(&self) -> usize {
        self.live.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::Ceremony;
    use crate::signing::orchard::params_for;
    use crate::signing::{LocalQuorum, Quorum};

    fn alpha(n: u8) -> Randomizer<PallasBlake2b512> {
        let mut b = [0u8; 32];
        b[0] = n;
        Randomizer::deserialize(&b).unwrap()
    }

    fn vault(t: u16, n: u16) -> Vec<VaultKeys> {
        Ceremony::new(t, n)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .map(|(_, k)| k)
            .collect()
    }

    /// Driving the two rounds across (in-process) participants produces, for
    /// each action, a signature Orchard would accept under that action's
    /// randomized key — the same thing the in-process path produces, reached
    /// without any one participant seeing another's share.
    #[test]
    fn a_distributed_round_trip_signs_every_action() {
        let keys = vault(2, 3);
        let group = keys[0].public_package.verifying_key();
        let public = keys[0].public_package.clone();
        let mut q = LocalQuorum::new(keys.clone());
        let sighash = [0x42u8; 32];
        let alphas = [alpha(11), alpha(12)];

        let r1 = q.round1(1, sighash, &alphas, 0);
        assert!(r1.len() >= 2, "at least a threshold committed");
        let chosen: Vec<_> = r1.keys().take(2).copied().collect();
        let packages: Vec<_> = (0..alphas.len())
            .map(|i| {
                let commits = chosen.iter().map(|id| (*id, r1[id][i])).collect();
                frost_core::SigningPackage::new(commits, &sighash)
            })
            .collect();
        let r2 = q.round2(1, &chosen, &packages);
        assert_eq!(r2.len(), 2, "the chosen two each signed");

        for (i, a) in alphas.iter().enumerate() {
            let shares = chosen.iter().map(|id| (*id, r2[id][i].clone())).collect();
            let params = params_for(&group, *a);
            let sig = crate::signing::orchard::aggregate(&packages[i], &shares, &public, &params)
                .unwrap();
            assert!(
                params
                    .randomized_verifying_key()
                    .verify(&sighash, &sig)
                    .is_ok(),
                "action {} did not verify",
                i
            );
        }
    }

    #[test]
    fn a_nonce_is_committed_once_and_signed_once() {
        let mut p = Participant::new(vault(2, 2).remove(0));
        let sighash = [1u8; 32];
        let alphas = vec![alpha(5)];
        p.round1(7, sighash, alphas.clone(), 0, &mut rand::rngs::OsRng)
            .unwrap();
        // A second round one for the same request would re-commit the nonce.
        assert_eq!(
            p.round1(7, sighash, alphas, 0, &mut rand::rngs::OsRng)
                .unwrap_err(),
            CustodyError::AlreadyOpen
        );
        assert_eq!(p.open_requests(), 1);
        // Round two for a request that was never opened is refused.
        let pkg = {
            // any well-formed package for the shape check to pass first? shape
            // is checked after lookup, so an unknown id fails at lookup.
            Vec::new()
        };
        assert_eq!(
            p.round2(999, &pkg).unwrap_err(),
            CustodyError::NoSuchRequest
        );
    }

    #[test]
    fn an_abandoned_request_releases_its_nonces() {
        let mut p = Participant::new(vault(2, 2).remove(0));
        p.round1(1, [0u8; 32], vec![alpha(1)], 0, &mut rand::rngs::OsRng)
            .unwrap();
        assert_eq!(p.open_requests(), 1);
        // A round one far past the TTL clears the stale one first.
        p.round1(
            2,
            [0u8; 32],
            vec![alpha(2)],
            REQUEST_TTL_SECS + 1,
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        assert_eq!(p.open_requests(), 1, "the abandoned request was dropped");
    }

    #[test]
    fn a_quorum_one_short_produces_no_usable_package() {
        // Only one of two required participants answers round one.
        let keys = vault(2, 3);
        let mut solo = LocalQuorum::new(vec![keys[0].clone()]);
        let r1 = solo.round1(1, [9u8; 32], &[alpha(1)], 0);
        assert_eq!(r1.len(), 1, "one commitment is below the threshold of two");
    }
}

/// The same discipline for Ed25519's ed25519 vault, which is simpler: one
/// message, one signature, and no re-randomization — so one nonce per request
/// rather than one per action.
pub mod ed25519 {
    use std::collections::BTreeMap;

    use crate::ceremony::{IdentifierFor, Ed25519, ThresholdKeys};
    use crate::signing::Session;

    use super::{CustodyError, REQUEST_TTL_SECS};

    pub type Id = IdentifierFor<Ed25519>;
    pub type Keys = ThresholdKeys<Ed25519>;

    struct Live {
        message: Vec<u8>,
        session: Option<Session<Ed25519>>,
        opened_at: u64,
    }

    /// One Ed25519 share, and the requests it has open.
    pub struct Participant {
        keys: Keys,
        live: BTreeMap<u64, Live>,
    }

    impl Participant {
        pub fn new(keys: Keys) -> Participant {
            Participant {
                keys,
                live: BTreeMap::new(),
            }
        }

        pub fn id(&self) -> Id {
            *self.keys.key_package.identifier()
        }

        /// Round one: commit to a nonce for this message.
        pub fn round1<R: rand_core::RngCore + rand_core::CryptoRng>(
            &mut self,
            request_id: u64,
            message: Vec<u8>,
            now: u64,
            rng: &mut R,
        ) -> Result<frost_core::round1::SigningCommitments<Ed25519>, CustodyError> {
            self.drop_expired(now);
            if self.live.contains_key(&request_id) {
                return Err(CustodyError::AlreadyOpen);
            }
            let s = Session::begin(self.id(), &self.keys, rng);
            let commitments = s.commitments();
            self.live.insert(
                request_id,
                Live {
                    message,
                    session: Some(s),
                    opened_at: now,
                },
            );
            Ok(commitments)
        }

        /// Round two: release the share and consume the nonce.
        pub fn round2(
            &mut self,
            request_id: u64,
            package: &frost_core::SigningPackage<Ed25519>,
        ) -> Result<frost_core::round2::SignatureShare<Ed25519>, CustodyError> {
            let mut req = self
                .live
                .remove(&request_id)
                .ok_or(CustodyError::NoSuchRequest)?;
            if package.message().as_slice() != req.message.as_slice() {
                return Err(CustodyError::WrongMessage);
            }
            let session = req.session.take().ok_or(CustodyError::NoSuchRequest)?;
            Ok(session.sign(&self.keys, package)?)
        }

        pub fn drop_expired(&mut self, now: u64) {
            self.live
                .retain(|_, r| now.saturating_sub(r.opened_at) < REQUEST_TTL_SECS);
        }

        pub fn open_requests(&self) -> usize {
            self.live.len()
        }
    }
}
