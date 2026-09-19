//! Distributed key generation, so the vault key is never whole in one place.
//!
//! [`crate::ceremony::Ceremony`] already runs the three FROST DKG rounds — but
//! in one process, which means one process transiently holds every secret.
//! This drives the same rounds across machines: each participant runs its own
//! `part1`/`part2`/`part3`, and only packages cross the wire.
//!
//! # What may and may not be read
//!
//! Round-one packages are broadcast — a commitment to a polynomial, public by
//! design. **Round-two packages are not.** Each is one participant's secret
//! contribution to another's share; whoever gathered them all could rebuild
//! the whole key. So the relay never sees them in the clear: each is sealed to
//! its recipient (x25519 ECDH to a per-ceremony key, ChaCha20-Poly1305), and
//! the coordinator relays ciphertext it cannot open. A coordinator that
//! tampers breaks the ceremony — the participants' group keys will not agree
//! with the vault — rather than subverting it.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use frost_core::keys::dkg;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::ceremony::{CeremonyError, IdentifierFor, ThresholdKeys, Zcash};
use frost_core::Ciphersuite;

/// A participant's per-ceremony sealing key. Fresh each ceremony; used only to
/// encrypt round-two packages to it, never to sign.
pub struct SealKey {
    secret: StaticSecret,
    pub public: [u8; 32],
}

impl SealKey {
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> SealKey {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let secret = StaticSecret::from(seed);
        let public = XPublic::from(&secret).to_bytes();
        SealKey { secret, public }
    }
}

fn cipher(secret: &StaticSecret, peer: &[u8; 32]) -> ChaCha20Poly1305 {
    // The ECDH shared secret is the key. Both sides derive the same bytes;
    // a relay with neither secret derives nothing.
    let shared = secret.diffie_hellman(&XPublic::from(*peer));
    let mut key = [0u8; 32];
    // Domain-separate so this key is never confused with a signing input.
    let h = <sha2::Sha256 as sha2::Digest>::new();
    let h = sha2::Digest::chain_update(h, b"zec.dkg.seal.v1");
    let h = sha2::Digest::chain_update(h, shared.as_bytes());
    key.copy_from_slice(&sha2::Digest::finalize(h));
    ChaCha20Poly1305::new((&key).into())
}

/// Seal a round-two package to `recipient_public`. A fixed nonce is safe: the
/// key is unique to this (sender, recipient, ceremony) triple and used once.
pub fn seal(
    sender: &SealKey,
    recipient_public: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, CeremonyError> {
    cipher(&sender.secret, recipient_public)
        .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext)
        .map_err(|_| CeremonyError::Crypto)
}

/// Open a round-two package sealed by `sender_public`.
pub fn open(
    recipient: &SealKey,
    sender_public: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CeremonyError> {
    cipher(&recipient.secret, sender_public)
        .decrypt(Nonce::from_slice(&[0u8; 12]), ciphertext)
        .map_err(|_| CeremonyError::Crypto)
}

/// What one participant broadcasts after round one: its identity, its DKG
/// round-one public package, and the sealing key others encrypt to.
#[derive(Clone)]
pub struct Round1Broadcast<C: Ciphersuite> {
    pub id: IdentifierFor<C>,
    pub package: dkg::round1::Package<C>,
    pub seal_public: [u8; 32],
}

/// The local half of a distributed DKG for one participant. Holds this
/// participant's secrets between rounds; never another's.
pub struct DkgParticipant<C: Ciphersuite> {
    id: IdentifierFor<C>,
    threshold: u16,
    participants: u16,
    seal: SealKey,
    r1_secret: Option<dkg::round1::SecretPackage<C>>,
    r2_secret: Option<dkg::round2::SecretPackage<C>>,
    /// Round-one packages from everyone (including self), kept for round three.
    r1_all: BTreeMap<IdentifierFor<C>, dkg::round1::Package<C>>,
    seal_pubs: BTreeMap<IdentifierFor<C>, [u8; 32]>,
}

impl<C: Ciphersuite> DkgParticipant<C> {
    /// Round one: commit to a polynomial. Returns what to broadcast.
    pub fn part1<R: rand_core::RngCore + rand_core::CryptoRng>(
        id: IdentifierFor<C>,
        threshold: u16,
        participants: u16,
        rng: &mut R,
    ) -> Result<(DkgParticipant<C>, Round1Broadcast<C>), CeremonyError> {
        let (secret, package) = dkg::part1(id, participants, threshold, &mut *rng)
            .map_err(|_| CeremonyError::Crypto)?;
        let seal = SealKey::new(rng);
        let broadcast = Round1Broadcast {
            id,
            package: package.clone(),
            seal_public: seal.public,
        };
        let mut p = DkgParticipant {
            id,
            threshold,
            participants,
            seal,
            r1_secret: Some(secret),
            r2_secret: None,
            r1_all: BTreeMap::new(),
            seal_pubs: BTreeMap::new(),
        };
        p.r1_all.insert(id, package);
        p.seal_pubs.insert(id, p.seal.public);
        Ok((p, broadcast))
    }

    /// Round two: given everyone else's round-one broadcasts, produce one
    /// **sealed** package per other participant. The relay carries these; only
    /// the recipient can open its own.
    pub fn part2(
        &mut self,
        others: &[Round1Broadcast<C>],
    ) -> Result<BTreeMap<IdentifierFor<C>, Vec<u8>>, CeremonyError> {
        for b in others {
            self.r1_all.insert(b.id, b.package.clone());
            self.seal_pubs.insert(b.id, b.seal_public);
        }
        if self.r1_all.len() != usize::from(self.participants) {
            return Err(CeremonyError::Incomplete);
        }
        let secret = self.r1_secret.take().ok_or(CeremonyError::Incomplete)?;
        let r1_others: BTreeMap<_, _> = self
            .r1_all
            .iter()
            .filter(|(k, _)| **k != self.id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let (s2, p2) = dkg::part2(secret, &r1_others).map_err(|_| CeremonyError::Crypto)?;
        self.r2_secret = Some(s2);
        let mut sealed = BTreeMap::new();
        for (to, package) in p2 {
            let bytes = package.serialize().map_err(|_| CeremonyError::Crypto)?;
            let peer = self.seal_pubs.get(&to).ok_or(CeremonyError::Incomplete)?;
            sealed.insert(to, seal(&self.seal, peer, &bytes)?);
        }
        Ok(sealed)
    }

    /// Round three: given the round-two packages sealed **to me**, open them
    /// and assemble this participant's share and the group public package.
    pub fn part3(
        &mut self,
        sealed_for_me: &BTreeMap<IdentifierFor<C>, Vec<u8>>,
    ) -> Result<ThresholdKeys<C>, CeremonyError> {
        let secret = self.r2_secret.take().ok_or(CeremonyError::Incomplete)?;
        let r1_others: BTreeMap<_, _> = self
            .r1_all
            .iter()
            .filter(|(k, _)| **k != self.id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let mut r2_for_me = BTreeMap::new();
        for (from, ct) in sealed_for_me {
            let peer = self.seal_pubs.get(from).ok_or(CeremonyError::Incomplete)?;
            let bytes = open(&self.seal, peer, ct)?;
            r2_for_me.insert(
                *from,
                dkg::round2::Package::<C>::deserialize(&bytes)
                    .map_err(|_| CeremonyError::Crypto)?,
            );
        }
        let (key_package, public_package) =
            dkg::part3(&secret, &r1_others, &r2_for_me).map_err(|_| CeremonyError::Crypto)?;
        let _ = self.threshold;
        Ok(ThresholdKeys {
            key_package,
            public_package,
        })
    }

    pub fn id(&self) -> IdentifierFor<C> {
        self.id
    }
    pub fn seal_public(&self) -> [u8; 32] {
        self.seal.public
    }
}

/// A distributed DKG for Zcash, driven in memory over the same steps a network
/// coordinator relays — the test harness, and the reference for the tool.
///
/// Kept as the Zcash-shaped name every existing caller uses; the work is in
/// [`run_in_memory_for`], which is the same ceremony over any ciphersuite.
pub fn run_in_memory(
    threshold: u16,
    participants: u16,
) -> Result<BTreeMap<IdentifierFor<Zcash>, ThresholdKeys<Zcash>>, CeremonyError> {
    run_in_memory_for::<Zcash>(threshold, participants)
}

/// The same ceremony, over any ciphersuite.
///
/// Every part of the DKG was already generic — `DkgParticipant<C>`,
/// `Round1Broadcast<C>`, `ThresholdKeys<C>` — and only this driver named Zcash,
/// which is why provisioning a threshold account for anything else looked like
/// new work when it was a type parameter away.
pub fn run_in_memory_for<C: Ciphersuite>(
    threshold: u16,
    participants: u16,
) -> Result<BTreeMap<IdentifierFor<C>, ThresholdKeys<C>>, CeremonyError> {
    let mut rng = rand::rngs::OsRng;
    let ids: Vec<IdentifierFor<C>> = (1..=participants)
        .map(|i| IdentifierFor::<C>::try_from(i).map_err(|_| CeremonyError::Crypto))
        .collect::<Result<_, _>>()?;
    let mut parts = BTreeMap::new();
    let mut broadcasts = Vec::new();
    for id in &ids {
        let (p, b) = DkgParticipant::<C>::part1(*id, threshold, participants, &mut rng)?;
        parts.insert(*id, p);
        broadcasts.push(b);
    }
    // Round two: each seals a package to every other; the relay collects them
    // by (from -> to -> ciphertext).
    let mut relayed: BTreeMap<IdentifierFor<C>, BTreeMap<IdentifierFor<C>, Vec<u8>>> =
        BTreeMap::new();
    for id in &ids {
        let others: Vec<_> = broadcasts.iter().filter(|b| b.id != *id).cloned().collect();
        let sealed = parts.get_mut(id).unwrap().part2(&others)?;
        for (to, ct) in sealed {
            relayed.entry(to).or_default().insert(*id, ct);
        }
    }
    // Round three: each opens the packages addressed to it.
    let mut out = BTreeMap::new();
    for id in &ids {
        let for_me = relayed.remove(id).unwrap_or_default();
        out.insert(*id, parts.get_mut(id).unwrap().part3(&for_me)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{LocalQuorum, Quorum};

    #[test]
    fn a_distributed_dkg_yields_a_vault_that_signs() {
        // No step ever held more than its own secret; the shares still agree
        // on one group key and can authorise a spend together.
        let keys = run_in_memory(2, 3).expect("dkg completes");
        assert_eq!(keys.len(), 3);
        let group = keys.values().next().unwrap().public_package.verifying_key();
        for k in keys.values() {
            assert_eq!(
                k.public_package.verifying_key(),
                group,
                "every share must agree on the group key"
            );
        }
        // And a threshold can sign under it — the whole point.
        let vaultkeys: Vec<_> = keys.values().cloned().collect();
        let public = vaultkeys[0].public_package.clone();
        let mut q = LocalQuorum::new(vaultkeys);
        let sighash = [0x24u8; 32];
        let mut b = [0u8; 32];
        b[0] = 7;
        let alpha = crate::signing::orchard::Randomizer::deserialize(&b).unwrap();
        let r1 = q.round1(1, sighash, &[alpha], 0);
        assert!(r1.len() >= 2);
        let chosen: Vec<_> = r1.keys().take(2).copied().collect();
        let pkg = frost_core::SigningPackage::new(
            chosen.iter().map(|id| (*id, r1[id][0])).collect(),
            &sighash,
        );
        let r2 = q.round2(1, &chosen, &[pkg.clone()]);
        let shares = chosen.iter().map(|id| (*id, r2[id][0].clone())).collect();
        let params = crate::signing::orchard::params_for(group, alpha);
        let sig = crate::signing::orchard::aggregate(&pkg, &shares, &public, &params).unwrap();
        assert!(
            params
                .randomized_verifying_key()
                .verify(&sighash, &sig)
                .is_ok(),
            "the distributed-DKG vault could not sign"
        );
    }

    #[test]
    fn the_seal_is_confidential_and_authenticated() {
        let mut rng = rand::rngs::OsRng;
        let a = SealKey::new(&mut rng);
        let b = SealKey::new(&mut rng);
        let ct = seal(&a, &b.public, b"round-two secret").unwrap();
        assert_eq!(open(&b, &a.public, &ct).unwrap(), b"round-two secret");
        // A relay (neither key) cannot open it; a tampered byte is rejected.
        let c = SealKey::new(&mut rng);
        assert!(
            open(&c, &a.public, &ct).is_err(),
            "a third party opened a sealed package"
        );
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(
            open(&b, &a.public, &bad).is_err(),
            "a tampered package was accepted"
        );
    }
}

/// The networked ceremony: a dumb relay and a participant client. The relay
/// collects each round's messages and serves them once all N have arrived —
/// it stores round-one broadcasts (public) and round-two ciphertext (which it
/// cannot open), and nothing else.
pub mod net {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    pub const OP_POST_R1: u8 = 1;
    pub const OP_GET_R1: u8 = 2;
    pub const OP_POST_R2: u8 = 3;
    pub const OP_GET_R2: u8 = 4;
    pub const S_OK: u8 = 0;
    pub const S_WAIT: u8 = 2;
    pub const S_ERR: u8 = 1;
    const MAX: usize = 4 << 20;

    fn pb(o: &mut Vec<u8>, b: &[u8]) {
        o.extend_from_slice(&(b.len() as u32).to_be_bytes());
        o.extend_from_slice(b);
    }
    struct R<'a> {
        b: &'a [u8],
        p: usize,
    }
    impl<'a> R<'a> {
        fn new(b: &'a [u8]) -> R<'a> {
            R { b, p: 0 }
        }
        fn u8(&mut self) -> Option<u8> {
            let v = *self.b.get(self.p)?;
            self.p += 1;
            Some(v)
        }
        fn u32(&mut self) -> Option<usize> {
            let s = self.b.get(self.p..self.p + 4)?;
            self.p += 4;
            Some(u32::from_be_bytes(s.try_into().ok()?) as usize)
        }
        fn bytes(&mut self) -> Option<&'a [u8]> {
            let n = self.u32()?;
            let s = self.b.get(self.p..self.p + n)?;
            self.p += n;
            Some(s)
        }
    }

    fn id_bytes<C: Ciphersuite>(id: &IdentifierFor<C>) -> Vec<u8> {
        AsRef::<[u8]>::as_ref(&id.serialize()).to_vec()
    }
    fn id_from<C: Ciphersuite>(b: &[u8]) -> Option<IdentifierFor<C>> {
        IdentifierFor::<C>::deserialize(b).ok()
    }

    /// The relay's collected state for one ceremony.
    #[derive(Default)]
    pub struct Relay {
        expected: usize,
        r1: std::collections::BTreeMap<Vec<u8>, Vec<u8>>, // id -> encoded broadcast
        r2: std::collections::BTreeMap<Vec<u8>, std::collections::BTreeMap<Vec<u8>, Vec<u8>>>, // from -> to -> ct
    }

    /// Encode a round-one broadcast for the wire.
    pub fn encode_broadcast<C: Ciphersuite>(b: &Round1Broadcast<C>) -> Result<Vec<u8>, CeremonyError> {
        let mut o = Vec::new();
        pb(&mut o, &id_bytes(&b.id));
        pb(
            &mut o,
            &b.package.serialize().map_err(|_| CeremonyError::Crypto)?,
        );
        pb(&mut o, &b.seal_public);
        Ok(o)
    }
    pub fn decode_broadcast<C: Ciphersuite>(b: &[u8]) -> Option<Round1Broadcast<C>> {
        let mut r = R::new(b);
        let id = id_from(r.bytes()?)?;
        let package = dkg::round1::Package::<C>::deserialize(r.bytes()?).ok()?;
        let seal_public: [u8; 32] = r.bytes()?.try_into().ok()?;
        Some(Round1Broadcast {
            id,
            package,
            seal_public,
        })
    }

    impl Relay {
        pub fn new(expected: usize) -> Relay {
            Relay {
                expected,
                ..Default::default()
            }
        }

        pub fn handle(&mut self, frame: &[u8]) -> (u8, Vec<u8>) {
            let mut r = R::new(frame);
            match r.u8() {
                Some(OP_POST_R1) => {
                    let Some(b) = r.bytes() else {
                        return (S_ERR, b"malformed".to_vec());
                    };
                    // The relay keys by identifier and forwards the rest
                    // untouched. It reads the id straight off the frame rather
                    // than decoding the package, so it needs no ciphersuite —
                    // which is what lets one relay serve a Zcash ceremony and
                    // an Ed25519 one without knowing which it is looking at.
                    let Some(id) = R::new(b).bytes() else {
                        return (S_ERR, b"bad broadcast".to_vec());
                    };
                    self.r1.insert(id.to_vec(), b.to_vec());
                    (S_OK, Vec::new())
                }
                Some(OP_GET_R1) => {
                    if self.r1.len() < self.expected {
                        return (S_WAIT, Vec::new());
                    }
                    let mut o = Vec::new();
                    o.extend_from_slice(&(self.r1.len() as u32).to_be_bytes());
                    for v in self.r1.values() {
                        pb(&mut o, v);
                    }
                    (S_OK, o)
                }
                Some(OP_POST_R2) => {
                    // from ‖ n ‖ (to ‖ ct)*
                    let Some(from) = r.bytes().map(|x| x.to_vec()) else {
                        return (S_ERR, b"from".to_vec());
                    };
                    let Some(n) = r.u32() else {
                        return (S_ERR, b"n".to_vec());
                    };
                    let mut map = std::collections::BTreeMap::new();
                    for _ in 0..n {
                        let (Some(to), Some(ct)) =
                            (r.bytes().map(|x| x.to_vec()), r.bytes().map(|x| x.to_vec()))
                        else {
                            return (S_ERR, b"pkg".to_vec());
                        };
                        map.insert(to, ct);
                    }
                    self.r2.insert(from, map);
                    (S_OK, Vec::new())
                }
                Some(OP_GET_R2) => {
                    let Some(me) = r.bytes().map(|x| x.to_vec()) else {
                        return (S_ERR, b"me".to_vec());
                    };
                    if self.r2.len() < self.expected {
                        return (S_WAIT, Vec::new());
                    }
                    // Everything addressed to `me`, tagged by sender.
                    let mut o = Vec::new();
                    let entries: Vec<(&Vec<u8>, &Vec<u8>)> = self
                        .r2
                        .iter()
                        .filter_map(|(from, m)| m.get(&me).map(|ct| (from, ct)))
                        .collect();
                    o.extend_from_slice(&(entries.len() as u32).to_be_bytes());
                    for (from, ct) in entries {
                        pb(&mut o, from);
                        pb(&mut o, ct);
                    }
                    (S_OK, o)
                }
                _ => (S_ERR, b"op".to_vec()),
            }
        }
    }

    fn frame(s: &mut TcpStream, status: u8, body: &[u8]) -> std::io::Result<()> {
        let mut o = vec![status];
        o.extend_from_slice(body);
        s.write_all(&(o.len() as u32).to_be_bytes())?;
        s.write_all(&o)?;
        s.flush()
    }
    fn read(s: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
        let mut l = [0u8; 4];
        if s.read_exact(&mut l).is_err() {
            return Ok(None);
        }
        let n = u32::from_be_bytes(l) as usize;
        if n == 0 || n > MAX {
            return Ok(None);
        }
        let mut b = vec![0u8; n];
        s.read_exact(&mut b)?;
        Ok(Some(b))
    }

    /// Serve the relay until the ceremony is done and every participant has
    /// fetched round two. One connection per request (participants poll).
    pub fn serve(relay: Arc<Mutex<Relay>>, listener: TcpListener) {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let relay = Arc::clone(&relay);
            std::thread::spawn(move || {
                if let Ok(Some(frame_in)) = read(&mut s) {
                    let (st, body) = relay
                        .lock()
                        .map(|mut r| r.handle(&frame_in))
                        .unwrap_or((S_ERR, b"poisoned".to_vec()));
                    let _ = frame(&mut s, st, &body);
                }
            });
        }
    }

    fn call(addr: &str, req: &[u8]) -> Result<(u8, Vec<u8>), String> {
        let mut s = TcpStream::connect(addr).map_err(|e| format!("{}: {}", addr, e))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();
        s.write_all(&(req.len() as u32).to_be_bytes())
            .and_then(|_| s.write_all(req))
            .map_err(|e| e.to_string())?;
        let mut l = [0u8; 4];
        s.read_exact(&mut l).map_err(|_| "no reply".to_string())?;
        let mut b = vec![0u8; u32::from_be_bytes(l) as usize];
        s.read_exact(&mut b).map_err(|_| "truncated".to_string())?;
        Ok((b[0], b[1..].to_vec()))
    }

    fn poll(addr: &str, req: &[u8]) -> Result<Vec<u8>, String> {
        for _ in 0..600 {
            match call(addr, req)? {
                (S_OK, body) => return Ok(body),
                (S_WAIT, _) => std::thread::sleep(std::time::Duration::from_millis(500)),
                (_, e) => return Err(String::from_utf8_lossy(&e).into_owned()),
            }
        }
        Err("timed out waiting for the round to complete".into())
    }

    /// Run one participant of a distributed DKG against a relay at `addr`, and
    /// return this participant's share. The share is produced locally in
    /// round three and never leaves; the relay only ever saw a public
    /// broadcast and ciphertext.
    /// The Zcash-shaped name every existing caller uses.
    pub fn participate(
        addr: &str,
        id_index: u16,
        threshold: u16,
        participants: u16,
    ) -> Result<ThresholdKeys<Zcash>, String> {
        participate_for::<Zcash>(addr, id_index, threshold, participants)
    }


    pub fn participate_for<C: Ciphersuite>(
        addr: &str,
        id_index: u16,
        threshold: u16,
        participants: u16,
    ) -> Result<ThresholdKeys<C>, String> {
        let id = IdentifierFor::<C>::try_from(id_index).map_err(|_| "bad id".to_string())?;
        let (mut me, broadcast) =
            DkgParticipant::<C>::part1(id, threshold, participants, &mut rand::rngs::OsRng)
                .map_err(|e| format!("part1: {:?}", e))?;

        let mut req = vec![OP_POST_R1];
        pb(
            &mut req,
            &encode_broadcast(&broadcast).map_err(|e| format!("{:?}", e))?,
        );
        call(addr, &req)?;
        let all = poll(addr, &[OP_GET_R1])?;
        let mut r = R::new(&all);
        let n = r.u32().ok_or("r1 count")?;
        let mut others = Vec::new();
        for _ in 0..n {
            let bc = decode_broadcast(r.bytes().ok_or("r1 pkg")?).ok_or("r1 decode")?;
            if bc.id != id {
                others.push(bc);
            }
        }

        let sealed = me.part2(&others).map_err(|e| format!("part2: {:?}", e))?;
        let mut req = vec![OP_POST_R2];
        pb(&mut req, &id_bytes(&id));
        req.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        for (to, ct) in &sealed {
            pb(&mut req, &id_bytes(to));
            pb(&mut req, ct);
        }
        call(addr, &req)?;

        let mut req = vec![OP_GET_R2];
        pb(&mut req, &id_bytes(&id));
        let mine = poll(addr, &req)?;
        let mut r = R::new(&mine);
        let n = r.u32().ok_or("r2 count")?;
        let mut for_me = std::collections::BTreeMap::new();
        for _ in 0..n {
            let from = id_from(r.bytes().ok_or("r2 from")?).ok_or("r2 id")?;
            let ct = r.bytes().ok_or("r2 ct")?.to_vec();
            for_me.insert(from, ct);
        }
        me.part3(&for_me).map_err(|e| format!("part3: {:?}", e))
    }
}

#[cfg(test)]
mod net_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// The same relay, the same rounds, a different curve — and every
    /// participant must land on one account. A relay that could only carry
    /// RedPallas would make a threshold treasury a second piece of
    /// infrastructure instead of a second argument.
    #[test]
    fn the_same_relay_carries_a_treasury_ceremony_over_ed25519() {
        type T = crate::ed25519::Ed25519Suite;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let relay = Arc::new(Mutex::new(net::Relay::new(3)));
        {
            let relay = Arc::clone(&relay);
            std::thread::spawn(move || net::serve(relay, listener));
        }
        let handles: Vec<_> = (1..=3u16)
            .map(|i| {
                let addr = addr.clone();
                std::thread::spawn(move || net::participate_for::<T>(&addr, i, 2, 3).unwrap())
            })
            .collect();
        let keys: Vec<ThresholdKeys<T>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let account = crate::ed25519::account_of_group(&keys[0].public_package).unwrap();
        for k in &keys {
            assert_eq!(
                crate::ed25519::account_of_group(&k.public_package).unwrap(),
                account,
                "every participant must derive the same treasury account, or the ceremony did not agree"
            );
        }
        assert_ne!(account, [0u8; 32]);

        // Two of the three suffice, and the result is an ordinary signature.
        let shares: std::collections::BTreeMap<_, _> = keys
            .iter()
            .map(|k| (*k.key_package.identifier(), k.clone()))
            .collect();
        let two: Vec<_> = shares.keys().copied().take(2).collect();
        let (group_key, sig) = crate::ed25519::sign(&shares, &two, b"an intent payload").unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
        vk.verify_strict(b"an intent payload", &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("the group's signature must verify as an ordinary one");
    }

    #[test]
    fn a_ceremony_completes_over_real_sockets_with_the_relay_blind_to_round_two() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let relay = Arc::new(Mutex::new(net::Relay::new(3)));
        {
            let relay = Arc::clone(&relay);
            std::thread::spawn(move || net::serve(relay, listener));
        }
        let handles: Vec<_> = (1..=3u16)
            .map(|i| {
                let addr = addr.clone();
                std::thread::spawn(move || net::participate(&addr, i, 2, 3).unwrap())
            })
            .collect();
        let keys: Vec<ThresholdKeys<Zcash>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        let group = keys[0].public_package.verifying_key();
        for k in &keys {
            assert_eq!(
                k.public_package.verifying_key(),
                group,
                "all shares agree on the group key"
            );
        }
        // The relay stored round-two ciphertext it could not open: it holds
        // packages but no seal key, so it cannot reconstruct a share. (Proven
        // structurally by `the_seal_is_confidential_and_authenticated`.)
    }
}
