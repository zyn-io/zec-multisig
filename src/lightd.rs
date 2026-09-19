//! The block server's wire protocol, and a client for it.
//!
//! Length-prefixed frames over TCP, one request per frame, like the Zyn RPC.
//! Everything a wallet needs to scan and spend from a device that holds its
//! own keys: what chain this is, compact blocks in ranges, a full transaction
//! by id, a tree state to seed a note tree, and a way to broadcast. Nothing
//! that takes a key, and — with one deliberate exception — nothing that takes
//! an address.
//!
//! # The exception, and why it is one
//!
//! `UTXOS` takes a transparent address. It has to: a compact block carries
//! only Orchard actions, so there is nothing client-side to scan for
//! transparent funds, and the alternative — shipping every transparent output
//! in every block — is not a trade anyone would take.
//!
//! What it costs is the association between a t-address and whoever asked.
//! What it buys is that a holder can be paid by an exchange at all, since
//! every exchange pays out transparent. The address itself is public on the
//! chain either way, and the wallet is expected to shield the funds
//! immediately (see `crate::transparent`), so the window in which the
//! association means anything is short. Shielded balances remain invisible to
//! this server, which is the property that actually matters.
//!
//! ```text
//!   op 1 INFO                          -> network:u8 tip:u64 branch:u32 estimated:u64
//!   op 2 BLOCKS from:u64 count:u32     -> n:u32 (len:u32 compact-block)*
//!   op 3 TX txid:32                    -> len:u32 raw
//!   op 4 SEND len:u32 raw              -> len:u16 txid-hex
//!   op 5 TREESTATE height:u64 pool:u8  -> root:32 len:u32 frontier
//!   op 6 UTXOS len:u16 t-address       -> n:u32 (txid:32 index:u32 value:u64
//!                                                height:u64 len:u16 script)*
//! ```
//!
//! A TREESTATE below the pool's activation height answers with an all-zero
//! root and an empty frontier: the tree does not exist yet, and a wallet
//! born there starts it empty. INFO's `estimated` is the height the node
//! believes the chain is at; while it exceeds `tip` the node is syncing.
//!
//! A reply is `0` then the body, or `1 len:u16 message`.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::compact::CompactBlock;

pub const OP_INFO: u8 = 1;
pub const OP_BLOCKS: u8 = 2;
pub const OP_TX: u8 = 3;
pub const OP_SEND: u8 = 4;
pub const OP_TREESTATE: u8 = 5;
pub const OP_UTXOS: u8 = 6;

pub const NET_MAINNET: u8 = 1;
pub const NET_TESTNET: u8 = 2;

/// Blocks per request. Enough to amortise the round trip, small enough to
/// keep a reply under a few megabytes on a busy chain.
pub const MAX_BLOCKS: u32 = 1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Info {
    pub network: u8,
    pub tip: u64,
    pub branch: u32,
    /// The chain height the node believes exists. Equals `tip` once synced.
    pub estimated: u64,
}

impl Info {
    /// Still catching up, by more than a few blocks.
    pub fn syncing(&self) -> bool {
        self.estimated > self.tip + 20
    }
}

#[derive(Debug)]
pub enum LightError {
    Io(String),
    Server(String),
    Malformed(&'static str),
}

impl std::fmt::Display for LightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightError::Io(e) => write!(f, "block server unreachable: {}", e),
            LightError::Server(e) => write!(f, "block server refused: {}", e),
            LightError::Malformed(w) => write!(f, "malformed reply: {}", w),
        }
    }
}

pub fn write_frame(s: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    s.write_all(&(body.len() as u32).to_be_bytes())?;
    s.write_all(body)?;
    s.flush()
}

pub fn read_frame(s: &mut TcpStream, max: usize) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; n];
    s.read_exact(&mut body)?;
    Ok(body)
}

/// The server's side of the encoding, so both ends are written once and
/// tested against each other.
pub mod reply {
    use super::*;

    pub fn ok(body: Vec<u8>) -> Vec<u8> {
        let mut o = vec![0u8];
        o.extend_from_slice(&body);
        o
    }

    pub fn err(msg: &str) -> Vec<u8> {
        let msg = &msg.as_bytes()[..msg.len().min(u16::MAX as usize)];
        let mut o = vec![1u8];
        o.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        o.extend_from_slice(msg);
        o
    }

    pub fn info(i: Info) -> Vec<u8> {
        let mut o = vec![i.network];
        o.extend_from_slice(&i.tip.to_le_bytes());
        o.extend_from_slice(&i.branch.to_le_bytes());
        o.extend_from_slice(&i.estimated.to_le_bytes());
        ok(o)
    }

    /// The tree does not exist at this height.
    pub fn no_tree() -> Vec<u8> {
        tree_state([0u8; 32], &[])
    }

    pub fn blocks(encoded: &[Vec<u8>]) -> Vec<u8> {
        let mut o = (encoded.len() as u32).to_le_bytes().to_vec();
        for b in encoded {
            o.extend_from_slice(&(b.len() as u32).to_le_bytes());
            o.extend_from_slice(b);
        }
        ok(o)
    }

    pub fn transaction(raw: &[u8]) -> Vec<u8> {
        let mut o = (raw.len() as u32).to_le_bytes().to_vec();
        o.extend_from_slice(raw);
        ok(o)
    }

    pub fn sent(txid_hex: &str) -> Vec<u8> {
        let mut o = (txid_hex.len() as u16).to_le_bytes().to_vec();
        o.extend_from_slice(txid_hex.as_bytes());
        ok(o)
    }

    pub fn utxos(list: &[crate::lightd::Utxo]) -> Vec<u8> {
        let mut out = (list.len() as u32).to_le_bytes().to_vec();
        for u in list {
            out.extend_from_slice(&u.txid);
            out.extend_from_slice(&u.index.to_le_bytes());
            out.extend_from_slice(&u.value.to_le_bytes());
            out.extend_from_slice(&u.height.to_le_bytes());
            out.extend_from_slice(&(u.script.len() as u16).to_le_bytes());
            out.extend_from_slice(&u.script);
        }
        ok(out)
    }

    pub fn tree_state(root: [u8; 32], frontier: &[u8]) -> Vec<u8> {
        let mut o = root.to_vec();
        o.extend_from_slice(&(frontier.len() as u32).to_le_bytes());
        o.extend_from_slice(frontier);
        ok(o)
    }
}

/// One unspent transparent output, as the server reports it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Utxo {
    pub txid: [u8; 32],
    pub index: u32,
    pub value: u64,
    pub height: u64,
    /// The `scriptPubKey` it pays to; the wallet needs it to spend.
    pub script: Vec<u8>,
}

/// A request, decoded. The server matches on this.
#[derive(Clone, PartialEq, Eq, Debug)]

pub enum Request {
    Info,
    Blocks {
        from: u64,
        count: u32,
    },
    Transaction([u8; 32]),
    Send(Vec<u8>),
    TreeState {
        height: u64,
        pool: orchard::ValuePool,
    },
    /// Unspent transparent outputs paying one address. The only request that
    /// names an address; see the module docs.
    Utxos(String),
}

impl Request {
    pub fn decode(req: &[u8]) -> Result<Request, &'static str> {
        let Some(&op) = req.first() else {
            return Err("empty request");
        };
        let mut d = Rd(req, 1);
        match op {
            OP_INFO => Ok(Request::Info),
            OP_BLOCKS => Ok(Request::Blocks {
                from: d.u64().ok_or("malformed range")?,
                count: d.u32().ok_or("malformed range")?.min(MAX_BLOCKS),
            }),
            OP_TX => Ok(Request::Transaction(
                d.take(32).ok_or("malformed txid")?.try_into().unwrap(),
            )),
            OP_SEND => {
                let n = d.u32().ok_or("malformed")? as usize;
                Ok(Request::Send(d.take(n).ok_or("malformed")?.to_vec()))
            }
            OP_UTXOS => {
                let n = d.u16().ok_or("malformed")? as usize;
                if n > 128 {
                    return Err("address too long");
                }
                let raw = d.take(n).ok_or("malformed")?;
                let addr = core::str::from_utf8(raw).map_err(|_| "address is not text")?;
                Ok(Request::Utxos(addr.to_string()))
            }
            OP_TREESTATE => {
                let height = d.u64().ok_or("malformed")?;
                let pool = match d.u8().ok_or("malformed")? {
                    0 => orchard::ValuePool::Orchard,
                    1 => orchard::ValuePool::Ironwood,
                    _ => return Err("unknown pool"),
                };
                Ok(Request::TreeState { height, pool })
            }
            _ => Err("unknown op"),
        }
    }
}

pub struct Client {
    addr: String,
}

struct Rd<'a>(&'a [u8], usize);
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.0.get(self.1..self.1 + n)?;
        self.1 += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

impl Client {
    pub fn new(addr: &str) -> Client {
        Client {
            addr: addr.to_string(),
        }
    }

    fn call(&self, body: &[u8]) -> Result<Vec<u8>, LightError> {
        let mut s = TcpStream::connect(&self.addr).map_err(|e| LightError::Io(e.to_string()))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .ok();
        write_frame(&mut s, body).map_err(|e| LightError::Io(e.to_string()))?;
        let reply = read_frame(&mut s, 64 << 20).map_err(|e| LightError::Io(e.to_string()))?;
        unwrap_reply(&reply)
    }
}

/// Strip the status byte, or turn a server error into `LightError::Server`.
pub fn unwrap_reply(reply: &[u8]) -> Result<Vec<u8>, LightError> {
    {
        match reply.first() {
            Some(0) => Ok(reply[1..].to_vec()),
            Some(1) => {
                let n = u16::from_le_bytes([
                    reply.get(1).copied().unwrap_or(0),
                    reply.get(2).copied().unwrap_or(0),
                ]) as usize;
                Err(LightError::Server(
                    String::from_utf8_lossy(reply.get(3..3 + n).unwrap_or(b"")).to_string(),
                ))
            }
            _ => Err(LightError::Malformed("status")),
        }
    }
}

impl Client {
    pub fn info(&self) -> Result<Info, LightError> {
        let r = self.call(&[OP_INFO])?;
        let mut d = Rd(&r, 0);
        let network = d.u8().ok_or(LightError::Malformed("info"))?;
        let tip = d.u64().ok_or(LightError::Malformed("info"))?;
        let branch = d.u32().ok_or(LightError::Malformed("info"))?;
        let estimated = d.u64().unwrap_or(tip).max(tip);
        Ok(Info {
            network,
            tip,
            branch,
            estimated,
        })
    }

    pub fn blocks(&self, from: u64, count: u32) -> Result<Vec<CompactBlock>, LightError> {
        let mut b = vec![OP_BLOCKS];
        b.extend_from_slice(&from.to_le_bytes());
        b.extend_from_slice(&count.min(MAX_BLOCKS).to_le_bytes());
        let r = self.call(&b)?;
        let mut d = Rd(&r, 0);
        let n = d.u32().ok_or(LightError::Malformed("blocks"))?;
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let len = d.u32().ok_or(LightError::Malformed("block len"))? as usize;
            let bytes = d.take(len).ok_or(LightError::Malformed("block"))?;
            out.push(CompactBlock::decode(bytes).ok_or(LightError::Malformed("compact block"))?);
        }
        Ok(out)
    }

    pub fn transaction(&self, txid: &[u8; 32]) -> Result<Vec<u8>, LightError> {
        let mut b = vec![OP_TX];
        b.extend_from_slice(txid);
        let r = self.call(&b)?;
        let mut d = Rd(&r, 0);
        let len = d.u32().ok_or(LightError::Malformed("tx"))? as usize;
        Ok(d.take(len).ok_or(LightError::Malformed("tx"))?.to_vec())
    }

    pub fn send(&self, raw: &[u8]) -> Result<String, LightError> {
        let mut b = vec![OP_SEND];
        b.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        b.extend_from_slice(raw);
        let r = self.call(&b)?;
        let mut d = Rd(&r, 0);
        let n = d.u16().ok_or(LightError::Malformed("txid"))? as usize;
        Ok(String::from_utf8_lossy(d.take(n).ok_or(LightError::Malformed("txid"))?).to_string())
    }

    /// Unspent transparent outputs paying `address`.
    ///
    /// This tells the server an address, which nothing else here does — see
    /// the module docs for why that trade is worth making for transparent
    /// funds and would not be for shielded ones.
    pub fn utxos(&self, address: &str) -> Result<Vec<Utxo>, LightError> {
        let mut b = vec![OP_UTXOS];
        b.extend_from_slice(&(address.len() as u16).to_le_bytes());
        b.extend_from_slice(address.as_bytes());
        let r = self.call(&b)?;
        let mut d = Rd(&r, 0);
        let n = d.u32().ok_or(LightError::Malformed("utxo count"))? as usize;
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let txid: [u8; 32] = d
                .take(32)
                .ok_or(LightError::Malformed("utxo txid"))?
                .try_into()
                .unwrap();
            let index = d.u32().ok_or(LightError::Malformed("utxo index"))?;
            let value = d.u64().ok_or(LightError::Malformed("utxo value"))?;
            let height = d.u64().ok_or(LightError::Malformed("utxo height"))?;
            let len = d.u16().ok_or(LightError::Malformed("utxo script"))? as usize;
            let script = d
                .take(len)
                .ok_or(LightError::Malformed("utxo script"))?
                .to_vec();
            out.push(Utxo {
                txid,
                index,
                value,
                height,
                script,
            });
        }
        Ok(out)
    }

    pub fn tree_state(
        &self,
        height: u64,
        pool: orchard::ValuePool,
    ) -> Result<([u8; 32], Vec<u8>), LightError> {
        let mut b = vec![OP_TREESTATE];
        b.extend_from_slice(&height.to_le_bytes());
        b.push(match pool {
            orchard::ValuePool::Orchard => 0,
            orchard::ValuePool::Ironwood => 1,
        });
        let r = self.call(&b)?;
        let mut d = Rd(&r, 0);
        let root: [u8; 32] = d
            .take(32)
            .ok_or(LightError::Malformed("root"))?
            .try_into()
            .unwrap();
        let len = d.u32().ok_or(LightError::Malformed("frontier"))? as usize;
        Ok((
            root,
            d.take(len)
                .ok_or(LightError::Malformed("frontier"))?
                .to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_decode_to_what_the_client_sent() {
        let mut b = vec![OP_BLOCKS];
        b.extend_from_slice(&4_326_863u64.to_le_bytes());
        b.extend_from_slice(&5000u32.to_le_bytes());
        assert_eq!(
            Request::decode(&b),
            Ok(Request::Blocks {
                from: 4_326_863,
                count: MAX_BLOCKS
            })
        );
        let mut t = vec![OP_TREESTATE];
        t.extend_from_slice(&7u64.to_le_bytes());
        t.push(1);
        assert_eq!(
            Request::decode(&t),
            Ok(Request::TreeState {
                height: 7,
                pool: orchard::ValuePool::Ironwood
            })
        );
        assert_eq!(Request::decode(&[OP_TX, 1, 2]), Err("malformed txid"));
        assert_eq!(Request::decode(&[]), Err("empty request"));
        assert_eq!(Request::decode(&[99]), Err("unknown op"));
    }

    #[test]
    fn replies_round_trip_through_the_client_parsers() {
        let r = unwrap_reply(&reply::info(Info {
            network: NET_TESTNET,
            tip: 4_327_822,
            branch: 0xc8e7_1055,
            estimated: 4_327_900,
        }))
        .unwrap();
        let mut d = Rd(&r, 0);
        assert_eq!(
            (d.u8(), d.u64(), d.u32(), d.u64()),
            (
                Some(NET_TESTNET),
                Some(4_327_822),
                Some(0xc8e7_1055),
                Some(4_327_900)
            )
        );
        assert!(Info {
            network: NET_TESTNET,
            tip: 4_327_822,
            branch: 0,
            estimated: 4_327_900
        }
        .syncing());
        assert!(!Info {
            network: NET_TESTNET,
            tip: 4_327_822,
            branch: 0,
            estimated: 4_327_822
        }
        .syncing());

        let block = CompactBlock {
            height: 1,
            hash: [9; 32],
            txs: vec![],
        }
        .encode();
        let r = unwrap_reply(&reply::blocks(&[block.clone(), block.clone()])).unwrap();
        let mut d = Rd(&r, 0);
        assert_eq!(d.u32(), Some(2));
        let n = d.u32().unwrap() as usize;
        assert_eq!(CompactBlock::decode(d.take(n).unwrap()).unwrap().height, 1);

        let r = unwrap_reply(&reply::sent("abcd")).unwrap();
        let mut d = Rd(&r, 0);
        let n = d.u16().unwrap() as usize;
        assert_eq!(d.take(n), Some(&b"abcd"[..]));

        match unwrap_reply(&reply::err("no such block")) {
            Err(LightError::Server(m)) => assert_eq!(m, "no such block"),
            other => panic!("{:?}", other),
        }
    }
}
