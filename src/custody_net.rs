//! The custody signing protocol on a wire.
//!
//! A coordinator ([`RemoteQuorum`]) and a share-holder daemon speak two
//! messages. Everything that crosses is public — a sighash, the actions'
//! randomizers, nonce commitments, signature shares — so the wire needs no
//! confidentiality, only integrity, which the aggregation step already checks
//! (a tampered share does not combine). The share never crosses.
//!
//! Framing mirrors the node RPC: a `u32` length, then the body. Body: one op
//! byte, then fields. A daemon serves one [`crate::custodian::Participant`].

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;

use frost_rerandomized::Randomizer;
use reddsa::frost::redpallas::PallasBlake2b512;

use crate::ceremony::{Identifier, IdentifierFor, Ed25519, Zcash};
use crate::custodian::ed25519::Participant as Ed25519Participant;
use crate::custodian::Participant;
use crate::signing::{Quorum, Ed25519Quorum};

// The vault public key package: safe for a coordinator to hold.
pub type ZcashPublicPackage = reddsa::frost::redpallas::keys::PublicKeyPackage;

pub const OP_ROUND1: u8 = 1;
pub const OP_ROUND2: u8 = 2;
/// The Ed25519 vault's two rounds. Separate ops, because a daemon may hold a
/// share of one vault, the other, or both, and must never answer for a share
/// it does not have.
pub const OP_ED25519_ROUND1: u8 = 3;
pub const OP_ED25519_ROUND2: u8 = 4;
/// Threshold signing for a **treasury** account. The same Ed25519
/// ciphersuite and the same two rounds as the Ed25519 path — the message is an
/// opaque payload either way — but a different key, so it needs its own slot
/// rather than borrowing the vault's.
pub const OP_TREASURY_ROUND1: u8 = 5;
pub const OP_TREASURY_ROUND2: u8 = 6;
pub const STATUS_OK: u8 = 0;
pub const STATUS_ERR: u8 = 1;
const MAX_FRAME: usize = 4 << 20;

type Commitments = frost_core::round1::SigningCommitments<Zcash>;
type Package = frost_core::SigningPackage<Zcash>;
type Share = frost_core::round2::SignatureShare<Zcash>;

pub type Ed25519PublicPackage = frost_ed25519::keys::PublicKeyPackage;
type Ed25519Id = IdentifierFor<Ed25519>;
type Ed25519Commitments = frost_core::round1::SigningCommitments<Ed25519>;
type Ed25519Package = frost_core::SigningPackage<Ed25519>;
type Ed25519Share = frost_core::round2::SignatureShare<Ed25519>;

// ---- little-endian-free length-prefixed helpers ----

fn put_u32(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len());
    out.extend_from_slice(b);
}
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, p: 0 }
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
    fn u64(&mut self) -> Option<u64> {
        let s = self.b.get(self.p..self.p + 8)?;
        self.p += 8;
        Some(u64::from_be_bytes(s.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()?;
        let s = self.b.get(self.p..self.p + n)?;
        self.p += n;
        Some(s)
    }
}

// ---- request/reply encoders (public types only) ----

/// `OP_ROUND1 ‖ request_id ‖ sighash[32] ‖ n ‖ (alpha serialize)*`
pub fn encode_round1(
    request_id: u64,
    sighash: [u8; 32],
    alphas: &[Randomizer<PallasBlake2b512>],
) -> Vec<u8> {
    let mut out = vec![OP_ROUND1];
    out.extend_from_slice(&request_id.to_be_bytes());
    put_bytes(&mut out, &sighash);
    put_u32(&mut out, alphas.len());
    for a in alphas {
        put_bytes(&mut out, a.serialize().as_ref());
    }
    out
}

/// `OP_ROUND2 ‖ request_id ‖ n ‖ (package serialize)*`
pub fn encode_round2(request_id: u64, packages: &[Package]) -> Result<Vec<u8>, String> {
    let mut out = vec![OP_ROUND2];
    out.extend_from_slice(&request_id.to_be_bytes());
    put_u32(&mut out, packages.len());
    for pkg in packages {
        put_bytes(
            &mut out,
            &pkg.serialize().map_err(|_| "package".to_string())?,
        );
    }
    Ok(out)
}

/// Reply to round one: `identifier ‖ n ‖ (commitments serialize)*`
fn encode_commitments(id: Identifier, commitments: &[Commitments]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    put_bytes(&mut out, id.serialize().as_ref());
    put_u32(&mut out, commitments.len());
    for c in commitments {
        put_bytes(
            &mut out,
            &c.serialize().map_err(|_| "commitments".to_string())?,
        );
    }
    Ok(out)
}

/// Reply to round two: `identifier ‖ n ‖ (share serialize)*`
fn encode_shares(id: Identifier, shares: &[Share]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    put_bytes(&mut out, id.serialize().as_ref());
    put_u32(&mut out, shares.len());
    for s in shares {
        put_bytes(&mut out, &s.serialize());
    }
    Ok(out)
}

fn decode_commitments(b: &[u8]) -> Option<(Identifier, Vec<Commitments>)> {
    let mut r = Reader::new(b);
    let id = Identifier::deserialize(r.bytes()?).ok()?;
    let n = r.u32()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(Commitments::deserialize(r.bytes()?).ok()?);
    }
    Some((id, out))
}

fn decode_shares(b: &[u8]) -> Option<(Identifier, Vec<Share>)> {
    let mut r = Reader::new(b);
    let id = Identifier::deserialize(r.bytes()?).ok()?;
    let n = r.u32()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(Share::deserialize(r.bytes()?).ok()?);
    }
    Some((id, out))
}

// ---- the daemon side: apply a request to a Participant ----

/// Handle one framed request against a share. Pure, so a test drives it
/// without a socket. Returns the reply body (without the status byte).
pub fn handle(participant: &mut Participant, frame: &[u8], now: u64) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(frame);
    let op = r.u8().ok_or("empty")?;
    zcash_op(participant, op, &mut r, now)
}

fn zcash_op(
    participant: &mut Participant,
    op: u8,
    r: &mut Reader,
    now: u64,
) -> Result<Vec<u8>, String> {
    match op {
        OP_ROUND1 => {
            let request_id = r.u64().ok_or("request id")?;
            let sighash: [u8; 32] = r.bytes().and_then(|b| b.try_into().ok()).ok_or("sighash")?;
            let n = r.u32().ok_or("count")?;
            let mut alphas = Vec::with_capacity(n);
            for _ in 0..n {
                let a: [u8; 32] = r.bytes().and_then(|b| b.try_into().ok()).ok_or("alpha")?;
                alphas.push(Randomizer::deserialize(&a).map_err(|_| "alpha".to_string())?);
            }
            let commitments = participant
                .round1(request_id, sighash, alphas, now, &mut rand::rngs::OsRng)
                .map_err(|e| format!("{:?}", e))?;
            encode_commitments(participant.id(), &commitments)
        }
        OP_ROUND2 => {
            let request_id = r.u64().ok_or("request id")?;
            let n = r.u32().ok_or("count")?;
            let mut packages = Vec::with_capacity(n);
            for _ in 0..n {
                packages.push(
                    Package::deserialize(r.bytes().ok_or("package")?)
                        .map_err(|_| "package".to_string())?,
                );
            }
            let shares = participant
                .round2(request_id, &packages)
                .map_err(|e| format!("{:?}", e))?;
            encode_shares(participant.id(), &shares)
        }
        _ => Err("unknown op".into()),
    }
}

fn ed25519_op(
    participant: &mut Ed25519Participant,
    op: u8,
    r: &mut Reader,
    now: u64,
) -> Result<Vec<u8>, String> {
    match op {
        OP_ED25519_ROUND1 => {
            let request_id = r.u64().ok_or("request id")?;
            let message = r.bytes().ok_or("message")?.to_vec();
            let c = participant
                .round1(request_id, message, now, &mut rand::rngs::OsRng)
                .map_err(|e| format!("{:?}", e))?;
            let mut out = Vec::new();
            put_bytes(&mut out, ed25519_id_bytes(participant.id()).as_slice());
            put_bytes(
                &mut out,
                &c.serialize().map_err(|_| "commitments".to_string())?,
            );
            Ok(out)
        }
        OP_ED25519_ROUND2 => {
            let request_id = r.u64().ok_or("request id")?;
            let package = Ed25519Package::deserialize(r.bytes().ok_or("package")?)
                .map_err(|_| "package".to_string())?;
            let share = participant
                .round2(request_id, &package)
                .map_err(|e| format!("{:?}", e))?;
            let mut out = Vec::new();
            put_bytes(&mut out, ed25519_id_bytes(participant.id()).as_slice());
            put_bytes(&mut out, &share.serialize());
            Ok(out)
        }
        _ => Err("unknown op".into()),
    }
}

fn ed25519_id_bytes(id: Ed25519Id) -> Vec<u8> {
    AsRef::<[u8]>::as_ref(&id.serialize()).to_vec()
}

/// What one daemon holds: a share of the Zcash vault, of the Ed25519 vault, or
/// of both. Ops route by vault, and an op for a share this daemon does not
/// hold is refused rather than half-answered.
#[derive(Default)]
pub struct Custodian {
    pub zcash: Option<Participant>,
    pub ed25519: Option<Ed25519Participant>,
    /// The treasury share, if this box holds one. Same ciphersuite as
    /// `ed25519` and therefore the same participant type, but a distinct key:
    /// spending the vault and acting as the treasury are different authorities
    /// and must never be one slot.
    pub treasury: Option<Ed25519Participant>,
}

impl Custodian {
    pub fn handle(&mut self, frame: &[u8], now: u64) -> Result<Vec<u8>, String> {
        let mut r = Reader::new(frame);
        let op = r.u8().ok_or("empty")?;
        match op {
            OP_ROUND1 | OP_ROUND2 => {
                let p = self.zcash.as_mut().ok_or("no zcash share here")?;
                zcash_op(p, op, &mut r, now)
            }
            OP_ED25519_ROUND1 | OP_ED25519_ROUND2 => {
                let p = self.ed25519.as_mut().ok_or("no ed25519 share here")?;
                ed25519_op(p, op, &mut r, now)
            }
            OP_TREASURY_ROUND1 | OP_TREASURY_ROUND2 => {
                let p = self.treasury.as_mut().ok_or("no treasury share here")?;
                // Same rounds, different key. The op code is what keeps a
                // treasury request from ever reaching the vault's share.
                let inner = if op == OP_TREASURY_ROUND1 { OP_ED25519_ROUND1 } else { OP_ED25519_ROUND2 };
                ed25519_op(p, inner, &mut r, now)
            }
            _ => Err("unknown op".into()),
        }
    }

    pub fn drop_expired(&mut self, now: u64) {
        if let Some(p) = self.zcash.as_mut() {
            p.drop_expired(now);
        }
        if let Some(p) = self.ed25519.as_mut() {
            p.drop_expired(now);
        }
        if let Some(p) = self.treasury.as_mut() {
            p.drop_expired(now);
        }
    }
}

/// `OP_TREASURY_ROUND1 ‖ request_id ‖ message`
pub fn encode_treasury_round1(request_id: u64, message: &[u8]) -> Vec<u8> {
    let mut out = vec![OP_TREASURY_ROUND1];
    out.extend_from_slice(&request_id.to_be_bytes());
    put_bytes(&mut out, message);
    out
}

/// `OP_TREASURY_ROUND2 ‖ request_id ‖ package`
pub fn encode_treasury_round2(request_id: u64, package: &Ed25519Package) -> Result<Vec<u8>, String> {
    let mut out = vec![OP_TREASURY_ROUND2];
    out.extend_from_slice(&request_id.to_be_bytes());
    put_bytes(&mut out, &package.serialize().map_err(|_| "package".to_string())?);
    Ok(out)
}

/// `OP_ED25519_ROUND1 ‖ request_id ‖ message`
pub fn encode_sol_round1(request_id: u64, message: &[u8]) -> Vec<u8> {
    let mut out = vec![OP_ED25519_ROUND1];
    out.extend_from_slice(&request_id.to_be_bytes());
    put_bytes(&mut out, message);
    out
}

/// `OP_ED25519_ROUND2 ‖ request_id ‖ package`
pub fn encode_sol_round2(request_id: u64, package: &Ed25519Package) -> Result<Vec<u8>, String> {
    let mut out = vec![OP_ED25519_ROUND2];
    out.extend_from_slice(&request_id.to_be_bytes());
    put_bytes(
        &mut out,
        &package.serialize().map_err(|_| "package".to_string())?,
    );
    Ok(out)
}

pub fn read_ed25519_commitments(b: &[u8]) -> Option<(Ed25519Id, Ed25519Commitments)> {
    let mut r = Reader::new(b);
    let id = Ed25519Id::deserialize(r.bytes()?).ok()?;
    Some((id, Ed25519Commitments::deserialize(r.bytes()?).ok()?))
}

pub fn read_ed25519_share(b: &[u8]) -> Option<(Ed25519Id, Ed25519Share)> {
    let mut r = Reader::new(b);
    let id = Ed25519Id::deserialize(r.bytes()?).ok()?;
    Some((id, Ed25519Share::deserialize(r.bytes()?).ok()?))
}

/// Serve a share on a socket until killed. One thread per connection; a
/// connection may carry many requests (round one then round two).
pub fn serve(
    participant: std::sync::Arc<std::sync::Mutex<Custodian>>,
    listener: std::net::TcpListener,
    now: fn() -> u64,
) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let p = std::sync::Arc::clone(&participant);
        std::thread::spawn(move || {
            let _ = serve_conn(&p, stream, now);
        });
    }
}

fn read_frame(s: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    if s.read_exact(&mut len).is_err() {
        return Ok(None);
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        return Ok(None);
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_frame(s: &mut TcpStream, status: u8, body: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(status);
    out.extend_from_slice(body);
    s.write_all(&(out.len() as u32).to_be_bytes())?;
    s.write_all(&out)?;
    s.flush()
}

fn serve_conn(
    participant: &std::sync::Mutex<Custodian>,
    mut s: TcpStream,
    now: fn() -> u64,
) -> std::io::Result<()> {
    s.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    while let Some(frame) = read_frame(&mut s)? {
        let reply = {
            let mut p = participant
                .lock()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "poisoned"))?;
            p.handle(&frame, now())
        };
        match reply {
            Ok(body) => write_frame(&mut s, STATUS_OK, &body)?,
            Err(e) => write_frame(&mut s, STATUS_ERR, e.as_bytes())?,
        }
    }
    Ok(())
}

// ---- the coordinator side: a Quorum over sockets ----

/// The share-holders across a network. Holds no share — only their addresses.
/// A custodian unreachable in round one is simply not counted; one that drops
/// between rounds fails the attempt, and the coordinator retries.
pub struct RemoteQuorum {
    custodians: Vec<String>,
    timeout: std::time::Duration,
}

impl RemoteQuorum {
    pub fn new(custodians: Vec<String>) -> RemoteQuorum {
        RemoteQuorum {
            custodians,
            timeout: std::time::Duration::from_secs(30),
        }
    }

    fn call(&self, addr: &str, frame: &[u8]) -> Result<Vec<u8>, String> {
        let mut s = TcpStream::connect_timeout(
            &addr.parse().map_err(|_| format!("bad address {}", addr))?,
            self.timeout,
        )
        .map_err(|e| format!("{}: {}", addr, e))?;
        s.set_read_timeout(Some(self.timeout)).ok();
        s.set_write_timeout(Some(self.timeout)).ok();
        s.write_all(&(frame.len() as u32).to_be_bytes())
            .and_then(|_| s.write_all(frame))
            .map_err(|e| format!("{}: {}", addr, e))?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len)
            .map_err(|_| format!("{}: no reply", addr))?;
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut body)
            .map_err(|_| format!("{}: truncated", addr))?;
        match body.first() {
            Some(&STATUS_OK) => Ok(body[1..].to_vec()),
            _ => Err(format!(
                "{}: {}",
                addr,
                String::from_utf8_lossy(body.get(1..).unwrap_or_default())
            )),
        }
    }
}

impl Quorum for RemoteQuorum {
    fn round1(
        &mut self,
        request_id: u64,
        sighash: [u8; 32],
        alphas: &[Randomizer<PallasBlake2b512>],
        _now: u64,
    ) -> BTreeMap<Identifier, Vec<Commitments>> {
        let frame = encode_round1(request_id, sighash, alphas);
        let mut out = BTreeMap::new();
        for addr in self.custodians.clone() {
            match self
                .call(&addr, &frame)
                .ok()
                .and_then(|b| decode_commitments(&b))
            {
                Some((id, commitments)) if commitments.len() == alphas.len() => {
                    out.insert(id, commitments);
                }
                Some(_) => eprintln!(
                    "custody: {} answered round one with the wrong shape",
                    addr
                ),
                None => eprintln!("custody: {} did not answer round one", addr),
            }
        }
        out
    }

    fn round2(
        &mut self,
        request_id: u64,
        chosen: &[Identifier],
        packages: &[Package],
    ) -> BTreeMap<Identifier, Vec<Share>> {
        let Ok(frame) = encode_round2(request_id, packages) else {
            return BTreeMap::new();
        };
        let mut out = BTreeMap::new();
        // Only the chosen answered round one, but we do not track which address
        // is which id, so we ask all and keep the chosen ones' shares.
        for addr in self.custodians.clone() {
            if let Some((id, shares)) = self
                .call(&addr, &frame)
                .ok()
                .and_then(|b| decode_shares(&b))
            {
                if chosen.contains(&id) && shares.len() == packages.len() {
                    out.insert(id, shares);
                }
            }
        }
        out
    }
}

/// The Ed25519 share-holders across a network. Same posture as
/// [`RemoteQuorum`]: it holds no share, only addresses, and a custodian that
/// does not answer is simply not counted.
pub struct RemoteEd25519Quorum {
    custodians: Vec<String>,
    inner: RemoteQuorum,
}

impl RemoteEd25519Quorum {
    pub fn new(custodians: Vec<String>) -> RemoteEd25519Quorum {
        RemoteEd25519Quorum {
            custodians: custodians.clone(),
            inner: RemoteQuorum::new(custodians),
        }
    }
}

impl Ed25519Quorum for RemoteEd25519Quorum {
    fn round1(
        &mut self,
        request_id: u64,
        message: &[u8],
        _now: u64,
    ) -> BTreeMap<Ed25519Id, Ed25519Commitments> {
        let frame = encode_sol_round1(request_id, message);
        let mut out = BTreeMap::new();
        for addr in self.custodians.clone() {
            match self
                .inner
                .call(&addr, &frame)
                .ok()
                .and_then(|b| read_ed25519_commitments(&b))
            {
                Some((id, c)) => {
                    out.insert(id, c);
                }
                None => eprintln!("custody: {} did not answer ed25519 round one", addr),
            }
        }
        out
    }

    fn round2(
        &mut self,
        request_id: u64,
        chosen: &[Ed25519Id],
        package: &Ed25519Package,
    ) -> BTreeMap<Ed25519Id, Ed25519Share> {
        let Ok(frame) = encode_sol_round2(request_id, package) else {
            return BTreeMap::new();
        };
        let mut out = BTreeMap::new();
        for addr in self.custodians.clone() {
            if let Some((id, share)) = self
                .inner
                .call(&addr, &frame)
                .ok()
                .and_then(|b| read_ed25519_share(&b))
            {
                if chosen.contains(&id) {
                    out.insert(id, share);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::Ceremony;
    use crate::signing::orchard::{aggregate, params_for};

    fn alpha(n: u8) -> Randomizer<PallasBlake2b512> {
        let mut b = [0u8; 32];
        b[0] = n;
        Randomizer::deserialize(&b).unwrap()
    }

    /// The wire faithfully carries a full two-round signing: drive three
    /// daemons in memory through the encoders and decoders, aggregate, and
    /// verify — same result as the in-process path, having crossed the codec.
    #[test]
    fn the_protocol_round_trips_a_signature_over_the_wire() {
        let keys: Vec<_> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        let public = keys[0].public_package.clone();
        let group = *public.verifying_key();
        let mut daemons: Vec<Participant> = keys.into_iter().map(Participant::new).collect();
        let sighash = [0x55u8; 32];
        let alphas = [alpha(3), alpha(4)];

        // round one over the codec
        let req = encode_round1(9, sighash, &alphas);
        let mut r1 = BTreeMap::new();
        for d in &mut daemons {
            let reply = handle(d, &req, 0).unwrap();
            let (id, commits) = decode_commitments(&reply).unwrap();
            r1.insert(id, commits);
        }
        let chosen: Vec<_> = r1.keys().take(2).copied().collect();
        let packages: Vec<Package> = (0..alphas.len())
            .map(|i| Package::new(chosen.iter().map(|id| (*id, r1[id][i])).collect(), &sighash))
            .collect();

        // round two over the codec, only the chosen daemons
        let req2 = encode_round2(9, &packages).unwrap();
        let mut r2 = BTreeMap::new();
        for d in &mut daemons {
            if chosen.contains(&d.id()) {
                let reply = handle(d, &req2, 0).unwrap();
                let (id, shares) = decode_shares(&reply).unwrap();
                r2.insert(id, shares);
            }
        }
        for (i, a) in alphas.iter().enumerate() {
            let shares = chosen.iter().map(|id| (*id, r2[id][i].clone())).collect();
            let params = params_for(&group, *a);
            let sig = aggregate(&packages[i], &shares, &public, &params).unwrap();
            assert!(params
                .randomized_verifying_key()
                .verify(&sighash, &sig)
                .is_ok());
        }
    }

    /// The same for Ed25519: three daemons, two chosen, one message, one
    /// signature — and it verifies as ordinary ed25519, which is what the
    /// Ed25519 runtime will check.
    #[test]
    fn the_solana_protocol_round_trips_a_signature_over_the_wire() {
        use crate::ed25519 as custody;
        let keys: Vec<_> = custody::ceremony(2, 3, &mut rand::rngs::OsRng)
            .unwrap()
            .into_values()
            .collect();
        let public = keys[0].public_package.clone();
        let vault = custody::vault_address_of(&public);
        let mut daemons: Vec<Custodian> = keys
            .into_iter()
            .map(|k| Custodian {
                zcash: None,
                ed25519: Some(Ed25519Participant::new(k)),
                treasury: None,
            })
            .collect();
        let message = b"a ed25519 settlement message".to_vec();

        let req = encode_sol_round1(9, &message);
        let mut r1 = BTreeMap::new();
        for d in &mut daemons {
            let (id, c) = read_ed25519_commitments(&d.handle(&req, 0).unwrap()).unwrap();
            r1.insert(id, c);
        }
        let chosen: Vec<Ed25519Id> = r1.keys().take(2).copied().collect();
        let package = Ed25519Package::new(chosen.iter().map(|id| (*id, r1[id])).collect(), &message);

        let req2 = encode_sol_round2(9, &package).unwrap();
        let mut r2 = BTreeMap::new();
        for d in &mut daemons {
            let Some(p) = d.ed25519.as_ref() else { continue };
            if chosen.contains(&p.id()) {
                let (id, share) = read_ed25519_share(&d.handle(&req2, 0).unwrap()).unwrap();
                r2.insert(id, share);
            }
        }
        let sig = frost_ed25519::aggregate(&package, &r2, &public).unwrap();
        let bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
        custody::verify(&vault, &message, &bytes).unwrap();
    }

    /// A custodian commits its nonce to one message. Asked in round two to
    /// sign a different one under that nonce, it refuses — the coordinator is
    /// untrusted, and this is the check that says so.
    #[test]
    fn a_custodian_will_not_sign_a_message_it_did_not_commit_to() {
        use crate::ed25519 as custody;
        let keys: Vec<_> = custody::ceremony(2, 2, &mut rand::rngs::OsRng)
            .unwrap()
            .into_values()
            .collect();
        let mut d = Custodian {
            zcash: None,
            ed25519: Some(Ed25519Participant::new(keys[0].clone())),
                treasury: None,
        };
        let mut other = Ed25519Participant::new(keys[1].clone());

        let (id, c) =
            read_ed25519_commitments(&d.handle(&encode_sol_round1(1, b"pay alice"), 0).unwrap())
                .unwrap();
        let c2 = other
            .round1(1, b"pay mallory".to_vec(), 0, &mut rand::rngs::OsRng)
            .unwrap();
        let swapped = Ed25519Package::new(
            [(id, c), (other.id(), c2)].into_iter().collect(),
            b"pay mallory",
        );
        let err = d
            .handle(&encode_sol_round2(1, &swapped).unwrap(), 0)
            .unwrap_err();
        assert!(err.contains("WrongMessage"), "{}", err);
    }

    /// A daemon holding one vault's share does not answer for the other's.
    #[test]
    fn a_daemon_refuses_ops_for_a_share_it_does_not_hold() {
        let keys = Ceremony::new(2, 2)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .map(|(_, k)| k)
            .next()
            .unwrap();
        let mut d = Custodian {
            zcash: Some(Participant::new(keys)),
            ed25519: None,
                treasury: None,
        };
        let err = d.handle(&encode_sol_round1(1, b"anything"), 0).unwrap_err();
        assert_eq!(err, "no ed25519 share here");
        // And it still answers for the one it does hold.
        assert!(d
            .handle(&encode_round1(1, [7u8; 32], &[alpha(1)]), 0)
            .is_ok());
    }

    /// The coordinator side, on real sockets: three daemons on loopback, a
    /// `RemoteEd25519Quorum` that holds no share, and a signature that
    /// verifies. This is the shape a sequencer actually runs.
    #[test]
    fn a_remote_quorum_signs_for_solana_over_loopback() {
        use crate::ed25519 as custody;
        use std::sync::{Arc, Mutex};

        let keys: Vec<_> = custody::ceremony(2, 3, &mut rand::rngs::OsRng)
            .unwrap()
            .into_values()
            .collect();
        let public = keys[0].public_package.clone();
        let mut addrs = Vec::new();
        for k in keys {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            addrs.push(listener.local_addr().unwrap().to_string());
            let c = Arc::new(Mutex::new(Custodian {
                zcash: None,
                ed25519: Some(Ed25519Participant::new(k)),
                treasury: None,
            }));
            std::thread::spawn(move || serve(c, listener, || 0));
        }

        let message = b"one settlement, signed by machines that do not trust each other";
        let mut q = RemoteEd25519Quorum::new(addrs);
        let sig = custody::sign_with(&mut q, 2, &public, message, 0).unwrap();
        custody::verify(&custody::vault_address_of(&public), message, &sig).unwrap();
    }

    #[test]
    fn a_malformed_frame_is_an_error_not_a_panic() {
        let mut d = Participant::new(
            Ceremony::new(2, 2)
                .unwrap()
                .run(&mut rand::rngs::OsRng)
                .unwrap()
                .into_iter()
                .map(|(_, k)| k)
                .next()
                .unwrap(),
        );
        assert!(handle(&mut d, &[], 0).is_err());
        assert!(handle(&mut d, &[OP_ROUND1], 0).is_err());
        assert!(handle(&mut d, &[99], 0).is_err());
    }
}

/// One request to a custodian, length-prefixed both ways.
pub fn ask(addr: &str, frame: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(20))).ok();
    s.write_all(&(frame.len() as u32).to_be_bytes()).map_err(|e| e.to_string())?;
    s.write_all(frame).map_err(|e| e.to_string())?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).map_err(|e| e.to_string())?;
    let n = u32::from_be_bytes(len) as usize;
    if n > 1 << 20 {
        return Err("reply too large".into());
    }
    let mut body = vec![0u8; n];
    s.read_exact(&mut body).map_err(|e| e.to_string())?;
    // The reply is `status ‖ body`. Handing the status byte on to a decoder
    // makes every custodian error look like a malformed package.
    let (status, rest) = body.split_first().ok_or("empty reply")?;
    if *status != STATUS_OK {
        return Err(String::from_utf8_lossy(rest).into_owned());
    }
    Ok(rest.to_vec())
}
