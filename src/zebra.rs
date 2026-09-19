//! Talking to a real Zcash node.
//!
//! [`ChainView`](crate::watcher::ChainView) is what the watcher needs; this is
//! the first thing that actually implements it against a chain rather than a
//! mock. It speaks Zebra's JSON-RPC over HTTP — `getblockcount`,
//! `getaddresstxids`, `getrawtransaction`, `sendrawtransaction` — which are the
//! methods Zebra implements for lightwalletd compatibility.
//!
//! # Transparent only, and why that is a scaffold
//!
//! This watches **transparent** addresses. That is not the design: ZynZap's
//! deposits are shielded, custody is Orchard, and `zyn-custody`'s signing is
//! FROST over RedPallas because RedPallas is Orchard's spend-authorisation
//! scheme.
//!
//! What transparent buys is that the whole path either side of the shielded
//! part becomes real *now* — observe, confirm, attest, credit, and the
//! watcher's own reorg and replay logic — against testnet coins, before the
//! hardest pieces exist. Shielded deposits additionally need note decryption
//! with the vault's incoming viewing key; payouts additionally need Orchard
//! spend assembly. Neither is here.
//!
//! **This must not reach mainnet.** A transparent vault has no privacy and,
//! worse, its addresses are secp256k1 — a *third* signature scheme, which our
//! threshold custody does not cover. Guarded by [`Network`]: mainnet is refused
//! at construction rather than left to a deployment note nobody reads.
//!
//! # No memos, which forces the right addressing
//!
//! A transparent output carries no memo, so a deposit cannot say who it is
//! for. The account has to come from **which address received it** — one
//! address per account, watched individually.
//!
//! That is the design `DECISIONS` §8.11 was heading toward anyway, and the two
//! shipped systems studied there (SHLD, zenZEC) both arrived at it. The memo
//! path exists in [`crate::memo`] for the shielded case; this one cannot use
//! it, and is better for it.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::Value;
use crate::amount::Fixed;
use crate::account::AccountId;

use crate::watcher::{ChainView, ObservedDeposit};

/// One zatoshi in `Fixed`'s 1e18 scale.
const ZAT: i128 = 10_000_000_000;

/// Which chain a client is pointed at.
///
/// An enum rather than a string so that "is this mainnet?" is a question the
/// compiler can be asked, and [`Zebra::connect`] can refuse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    Testnet,
    Regtest,
    Mainnet,
}

#[derive(Debug)]
pub enum RpcError {
    Io(std::io::Error),
    /// The node answered, but not with JSON we can use.
    Malformed(&'static str),
    /// The node answered with an RPC error object.
    Node(String),
    /// A transparent vault was pointed at mainnet.
    RefusingMainnet,
    /// The node is on a different chain from the one we are configured for.
    WrongChain {
        want: &'static str,
        got: String,
    },
    /// An amount arrived without the integer field, leaving only a float.
    /// Refused rather than rounded — see [`Zebra::observe`].
    NonIntegerAmount,
}

impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> Self {
        RpcError::Io(e)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Io(e) => write!(f, "node unreachable: {}", e),
            RpcError::Malformed(w) => write!(f, "unexpected response shape: {}", w),
            RpcError::Node(m) => write!(f, "node refused: {}", m),
            RpcError::RefusingMainnet => {
                write!(f, "transparent custody is a testnet scaffold; refusing mainnet")
            }
            RpcError::WrongChain { want, got } => write!(
                f,
                "this node is on the {} chain, but we are configured for {} — refusing to run against the wrong chain",
                if got.is_empty() { "unknown" } else { got },
                want
            ),
            RpcError::NonIntegerAmount => {
                write!(f, "amount had no integer zatoshi field; refusing to read it as a float")
            }
        }
    }
}

/// The Orchard commitment tree at a height, as the node reports it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TreeState {
    pub height: u64,
    /// The tree's root, in the byte order `MerkleHashOrchard::to_bytes` uses.
    pub final_root: [u8; 32],
    /// The frontier, in the legacy `CommitmentTree` serialisation.
    pub final_state: Vec<u8>,
}

/// A blocking JSON-RPC client.
///
/// Hand-rolled over `TcpStream` rather than pulling an HTTP stack: the request
/// is one POST to a node on loopback or a private address, and an async runtime
/// bought nothing the rest of this workspace needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInfo {
    pub blocks: u64,
    pub estimated: u64,
    /// What the node calls its chain: `main`, `test`, `regtest`. The one
    /// authority on which chain this actually is — everything else is what we
    /// were configured to believe.
    pub chain: String,
}

pub struct Zebra {
    host: String,
    port: u16,
    /// `user:password`, base64-encoded, when the node wants it.
    auth: Option<String>,
    network: Network,
    timeout: Duration,
}

impl Zebra {
    pub fn connect(
        host: &str,
        port: u16,
        auth: Option<(&str, &str)>,
        network: Network,
    ) -> Result<Zebra, RpcError> {
        // Mainnet is allowed here now: the shielded vault is what runs on it.
        // The refusal moved to [`Self::observe`], which is the transparent
        // scaffold and the only part that was never meant to hold real money.
        Ok(Zebra {
            host: host.to_string(),
            port,
            auth: auth.map(|(u, p)| base64(format!("{}:{}", u, p).as_bytes())),
            network,
            timeout: Duration::from_secs(30),
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Refuse to proceed unless the node is on the chain we think it is.
    ///
    /// The check that has to exist before a vault holds real money. Every
    /// other safeguard assumes the chain under it is the configured one; get
    /// that wrong and a mainnet-configured vault happily credits testnet
    /// deposits, or hands out addresses nobody can pay. Nothing downstream can
    /// detect it, because everything downstream is consistent with itself.
    pub fn verify_network(&self) -> Result<(), RpcError> {
        let info = self.chain_info()?;
        let want = match self.network {
            Network::Mainnet => "main",
            Network::Testnet => "test",
            Network::Regtest => "regtest",
        };
        if info.chain != want {
            return Err(RpcError::WrongChain {
                want,
                got: info.chain,
            });
        }
        Ok(())
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "zyn",
            "method": method,
            "params": params,
        })
        .to_string();

        let mut req = format!(
            "POST / HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n",
            self.host,
            self.port,
            body.len()
        );
        if let Some(a) = &self.auth {
            req.push_str(&format!("Authorization: Basic {}\r\n", a));
        }
        req.push_str("\r\n");
        req.push_str(&body);

        let mut s = TcpStream::connect((self.host.as_str(), self.port))?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        s.write_all(req.as_bytes())?;
        s.flush()?;

        let mut raw = Vec::new();
        s.read_to_end(&mut raw)?;
        let split = find(&raw, b"\r\n\r\n").ok_or(RpcError::Malformed("no header terminator"))?;
        let payload = &raw[split + 4..];

        let v: Value =
            serde_json::from_slice(payload).map_err(|_| RpcError::Malformed("not json"))?;
        if let Some(e) = v.get("error") {
            if !e.is_null() {
                return Err(RpcError::Node(e.to_string()));
            }
        }
        v.get("result")
            .cloned()
            .ok_or(RpcError::Malformed("no result"))
    }

    pub fn block_count(&self) -> Result<u64, RpcError> {
        self.call("getblockcount", serde_json::json!([]))?
            .as_u64()
            .ok_or(RpcError::Malformed("block count"))
    }

    /// Unspent transparent outputs paying one address.
    ///
    /// Used only for the wallet's own receiving address — the doormat where
    /// exchange withdrawals land before being shielded. The vault never holds
    /// transparent funds and never calls this.
    pub fn address_utxos(&self, address: &str) -> Result<Vec<crate::lightd::Utxo>, RpcError> {
        let v = self.call(
            "getaddressutxos",
            serde_json::json!([{ "addresses": [address] }]),
        )?;
        let arr = v.as_array().ok_or(RpcError::Malformed("utxo list"))?;
        let mut out = Vec::with_capacity(arr.len());
        for u in arr {
            // Zebra reports the txid the way an explorer does: byte-reversed
            // from the internal form the wallet has to sign over.
            let txid_hex = u
                .get("txid")
                .and_then(Value::as_str)
                .ok_or(RpcError::Malformed("utxo txid"))?;
            let mut txid = [0u8; 32];
            for (i, b) in txid.iter_mut().enumerate() {
                let at = 62 - i * 2;
                *b = u8::from_str_radix(
                    txid_hex
                        .get(at..at + 2)
                        .ok_or(RpcError::Malformed("utxo txid"))?,
                    16,
                )
                .map_err(|_| RpcError::Malformed("utxo txid"))?;
            }
            let script_hex = u.get("script").and_then(Value::as_str).unwrap_or_default();
            let mut script = Vec::with_capacity(script_hex.len() / 2);
            for i in (0..script_hex.len()).step_by(2) {
                script.push(
                    u8::from_str_radix(&script_hex[i..i + 2], 16)
                        .map_err(|_| RpcError::Malformed("utxo script"))?,
                );
            }
            out.push(crate::lightd::Utxo {
                txid,
                index: u
                    .get("outputIndex")
                    .and_then(Value::as_u64)
                    .ok_or(RpcError::Malformed("utxo index"))? as u32,
                value: u
                    .get("satoshis")
                    .and_then(Value::as_u64)
                    .ok_or(RpcError::Malformed("utxo value"))?,
                height: u.get("height").and_then(Value::as_u64).unwrap_or(0),
                script,
            });
        }
        Ok(out)
    }

    /// Where the node is against the network: its own height, and the
    /// height it believes the chain has reached. Equal once synced.
    pub fn chain_info(&self) -> Result<ChainInfo, RpcError> {
        let v = self.call("getblockchaininfo", serde_json::json!([]))?;
        let blocks = v
            .get("blocks")
            .and_then(Value::as_u64)
            .ok_or(RpcError::Malformed("blocks"))?;
        let estimated = v
            .get("estimatedheight")
            .and_then(Value::as_u64)
            .unwrap_or(blocks)
            .max(blocks);
        let chain = v
            .get("chain")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok(ChainInfo {
            blocks,
            estimated,
            chain,
        })
    }

    fn address_txids(
        &self,
        addresses: &[String],
        start: u64,
        end: u64,
    ) -> Result<Vec<String>, RpcError> {
        let v = self.call(
            "getaddresstxids",
            serde_json::json!([{ "addresses": addresses, "start": start, "end": end }]),
        )?;
        let arr = v.as_array().ok_or(RpcError::Malformed("txid list"))?;
        Ok(arr
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect())
    }

    fn raw_transaction(&self, txid: &str) -> Result<Value, RpcError> {
        self.call("getrawtransaction", serde_json::json!([txid, 1]))
    }

    /// The transaction ids in one block.
    /// The whole block, serialised — one call instead of one per transaction.
    pub fn raw_block(&self, height: u64) -> Result<Vec<u8>, RpcError> {
        let v = self.call("getblock", serde_json::json!([height.to_string(), 0]))?;
        let hex = v.as_str().ok_or(RpcError::Malformed("raw block"))?;
        unhex(hex).ok_or(RpcError::Malformed("raw block is not hex"))
    }

    /// The hash of the block at `height`, as Zcash reports it.
    ///
    /// Asked of the node rather than computed from the header: a Zcash header
    /// is not a Bitcoin header, and re-deriving the hash here would be a second
    /// implementation of consensus that could disagree with the first. The
    /// reveal binds this value (§100.3), so a wrong one assigns the wrong
    /// items.
    pub fn block_hash(&self, height: u64) -> Result<[u8; 32], RpcError> {
        let v = self.call("getblockhash", serde_json::json!([height]))?;
        let hex = v.as_str().ok_or(RpcError::Malformed("block hash"))?;
        let raw = unhex(hex).ok_or(RpcError::Malformed("block hash is not hex"))?;
        // Zcash prints block hashes big-endian, the reverse of the internal
        // byte order. Kept exactly as printed, because that is what a person
        // comparing against a block explorer will have.
        raw.try_into()
            .map_err(|_| RpcError::Malformed("block hash is not 32 bytes"))
    }

    /// Like [`Zebra::connect`], but for reading a chain rather than
    /// custodying on it: mainnet is allowed. A wallet or a block server holds
    /// no vault key, so the guard that protects custody has nothing to
    /// protect here.
    pub fn connect_reader(
        host: &str,
        port: u16,
        auth: Option<(&str, &str)>,
        network: Network,
    ) -> Result<Zebra, RpcError> {
        Ok(Zebra {
            host: host.to_string(),
            port,
            auth: auth.map(|(u, p)| base64(format!("{}:{}", u, p).as_bytes())),
            network,
            timeout: Duration::from_secs(30),
        })
    }

    pub fn block_txids(&self, height: u64) -> Result<Vec<String>, RpcError> {
        let v = self.call("getblock", serde_json::json!([height.to_string(), 1]))?;
        let Some(txs) = v.get("tx").and_then(Value::as_array) else {
            return Err(RpcError::Malformed("block has no tx list"));
        };
        Ok(txs
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect())
    }

    /// One transaction's raw bytes, for shielded scanning.
    ///
    /// Verbose 0 rather than 1: a shielded deposit is not visible in the JSON
    /// view at all, and the only way to look at it is to parse the transaction
    /// and trial-decrypt its actions.
    pub fn raw_transaction_bytes(&self, txid: &str) -> Result<Vec<u8>, RpcError> {
        let v = self.call("getrawtransaction", serde_json::json!([txid, 0]))?;
        let hex = v.as_str().ok_or(RpcError::Malformed("raw transaction"))?;
        unhex(hex).ok_or(RpcError::Malformed("raw transaction is not hex"))
    }

    /// The Orchard note commitment tree as of `height`, from the node.
    ///
    /// This is the answer to the largest unknown in `DECISIONS` §13. The tree
    /// a spend is proved against includes every Orchard commitment since NU5,
    /// and rebuilding it from that height means reading millions of blocks
    /// one RPC at a time. Zebra serves the tree's **frontier** at any height
    /// (`z_gettreestate`, kept for lightwalletd), so a vault starts from the
    /// frontier at its creation height and appends from there — and the node
    /// also reports the root, which lets the vault check its own tree against
    /// the chain's at every step.
    pub fn tree_state(&self, height: u64) -> Result<TreeState, RpcError> {
        self.tree_state_of(height, orchard::ValuePool::Orchard)
    }

    /// The commitment tree of one pool. Ironwood (NU6.3) has its own tree and
    /// its own anchor; a note in one cannot be witnessed against the other.
    pub fn tree_state_of(
        &self,
        height: u64,
        pool: orchard::ValuePool,
    ) -> Result<TreeState, RpcError> {
        let v = self.call("z_gettreestate", serde_json::json!([height.to_string()]))?;
        let key = match pool {
            orchard::ValuePool::Orchard => "orchard",
            orchard::ValuePool::Ironwood => "ironwood",
        };
        let c = v
            .get(key)
            .and_then(|o| o.get("commitments"))
            .ok_or(RpcError::Malformed("pool commitments"))?;
        let root_hex = c
            .get("finalRoot")
            .and_then(Value::as_str)
            .ok_or(RpcError::Malformed("finalRoot"))?;
        // Not byte-reversed, unlike a txid: checked against a tree seeded from
        // the same call, in `tests/zebra_live.rs`.
        let final_root: [u8; 32] = unhex(root_hex)
            .and_then(|b| b.try_into().ok())
            .ok_or(RpcError::Malformed("finalRoot width"))?;
        let final_state = c
            .get("finalState")
            .and_then(Value::as_str)
            .and_then(unhex)
            .ok_or(RpcError::Malformed("finalState"))?;
        Ok(TreeState {
            height,
            final_root,
            final_state,
        })
    }

    /// How deep a transaction is, `None` if the node does not know it.
    ///
    /// `Some(0)` is the mempool. A transaction that was broadcast and is now
    /// `None` was dropped — or expired, which is what `expiry_height` is for.
    pub fn confirmations(&self, txid: &str) -> Result<Option<u64>, RpcError> {
        let v = match self.call("getrawtransaction", serde_json::json!([txid, 1])) {
            Ok(v) => v,
            Err(RpcError::Node(e))
                if e.contains("-5") || e.to_lowercase().contains("not found") =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        if let Some(c) = v.get("confirmations").and_then(Value::as_u64) {
            return Ok(Some(c));
        }
        match v.get("height").and_then(Value::as_i64) {
            Some(h) if h > 0 => Ok(Some(self.block_count()?.saturating_sub(h as u64) + 1)),
            _ => Ok(Some(0)),
        }
    }

    /// Hand a signed transaction to the network.
    pub fn send_raw_transaction(&self, hex: &str) -> Result<String, RpcError> {
        self.call("sendrawtransaction", serde_json::json!([hex]))?
            .as_str()
            .map(str::to_string)
            .ok_or(RpcError::Malformed("txid"))
    }

    /// Read the chain once, and answer from the result.
    ///
    /// [`ChainView`]'s methods are infallible and synchronous, which is right —
    /// a view is a snapshot and a snapshot cannot fail halfway. So all the I/O
    /// and all the failure live here, and what the watcher sees is a value.
    ///
    /// `from` should be where the watcher last scanned to; earlier heights are
    /// re-read only if asked for, and re-reading is harmless because the
    /// watcher deduplicates by txid.
    pub fn observe(
        &self,
        addresses: &BTreeMap<String, AccountId>,
        from: u64,
    ) -> Result<Observed, RpcError> {
        // Transparent custody was only ever a testnet scaffold: it watches
        // addresses in the clear and gives the vault no privacy at all.
        if self.network == Network::Mainnet {
            return Err(RpcError::RefusingMainnet);
        }
        let tip = self.block_count()?;
        let keys: Vec<String> = addresses.keys().cloned().collect();
        let mut deposits: BTreeMap<u64, Vec<ObservedDeposit>> = BTreeMap::new();

        if !keys.is_empty() && from <= tip {
            for txid in self.address_txids(&keys, from, tip)? {
                let tx = self.raw_transaction(&txid)?;
                let height = tx.get("height").and_then(Value::as_u64).unwrap_or(0);
                let Some(vout) = tx.get("vout").and_then(Value::as_array) else {
                    continue;
                };
                let id = hex32(&txid).ok_or(RpcError::Malformed("txid is not 32 bytes"))?;

                for out in vout {
                    // Money is read from the integer field or not at all. The
                    // sibling `value` is a JSON float, and a float is a lossy
                    // container for an exact quantity — the one place a bridge
                    // must never be approximately right.
                    let zat = out
                        .get("valueZat")
                        .or_else(|| out.get("valueSat"))
                        .and_then(Value::as_i64)
                        .ok_or(RpcError::NonIntegerAmount)?;

                    let Some(addrs) = out
                        .pointer("/scriptPubKey/addresses")
                        .and_then(Value::as_array)
                    else {
                        continue;
                    };
                    for a in addrs {
                        let Some(a) = a.as_str() else { continue };
                        let Some(account) = addresses.get(a) else {
                            continue;
                        };
                        deposits.entry(height).or_default().push(ObservedDeposit {
                            txid: id,
                            account: *account,
                            amount: Fixed(zat as i128 * ZAT),
                            height,
                            asset: None,
                        });
                    }
                }
            }
        }

        Ok(Observed {
            tip,
            deposits,
            forced: Vec::new(),
        })
    }
}

/// A snapshot of what the chain said, at one moment.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Observed {
    tip: u64,
    deposits: BTreeMap<u64, Vec<ObservedDeposit>>,
    /// Forced intents seen in the scanned range.
    forced: Vec<crate::shielded::ForcedSighting>,
}

impl Observed {
    /// Build one directly. For tests, and for replaying a recorded scan.
    pub fn new(tip: u64, deposits: Vec<ObservedDeposit>) -> Observed {
        let mut by_height: BTreeMap<u64, Vec<ObservedDeposit>> = BTreeMap::new();
        for d in deposits {
            by_height.entry(d.height).or_default().push(d);
        }
        Observed {
            tip,
            deposits: by_height,
            forced: Vec::new(),
        }
    }

    pub fn set_forced(&mut self, forced: Vec<crate::shielded::ForcedSighting>) {
        self.forced = forced;
    }

    /// Forced intents in the scanned range, in chain order.
    pub fn forced(&self) -> &[crate::shielded::ForcedSighting] {
        &self.forced
    }
}

impl ChainView for Observed {
    fn tip(&self) -> u64 {
        self.tip
    }

    fn deposits_at(&self, height: u64) -> Vec<ObservedDeposit> {
        self.deposits.get(&height).cloned().unwrap_or_default()
    }

    /// What the watched addresses had received as of `height`.
    ///
    /// Summed from the deposits themselves rather than read from
    /// `getaddressbalance`, because the watcher needs the figure **at the
    /// height it is crediting**, and a balance read at the tip would include
    /// deposits this batch is not crediting — which would attest more backing
    /// than the credits account for.
    ///
    /// This equals the balance only while the vault never spends. That holds
    /// today because nothing here can build a spending transaction, and it
    /// stops holding the moment payouts exist: at that point the sum has to
    /// account for inputs too, and this is the function that must change.
    fn balance_at(&self, height: u64) -> Option<Fixed> {
        if height > self.tip {
            return None;
        }
        let mut total = Fixed::ZERO;
        for (h, ds) in &self.deposits {
            if *h > height {
                break;
            }
            for d in ds {
                total = total.add(d.amount)?;
            }
        }
        Some(total)
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub(crate) fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(h: u64, n: u8, zat: i64) -> ObservedDeposit {
        ObservedDeposit {
            txid: [n; 32],
            account: [n; 32],
            amount: Fixed(zat as i128 * ZAT),
            height: h,
            asset: None,
        }
    }

    /// The guard that keeps a scaffold a scaffold.
    ///
    /// Connecting to mainnet is allowed — the shielded vault is meant to run
    /// there. What is refused is the **transparent** watcher, which reads
    /// addresses in the clear and was never meant to hold real money. The
    /// refusal happens before any RPC, so this needs no node.
    #[test]
    fn the_transparent_watcher_refuses_mainnet_but_connecting_does_not() {
        let main = Zebra::connect("127.0.0.1", 8232, None, Network::Mainnet)
            .expect("mainnet may be connected to");
        assert!(matches!(
            main.observe(&BTreeMap::new(), 0),
            Err(RpcError::RefusingMainnet)
        ));
        assert!(Zebra::connect("127.0.0.1", 18232, None, Network::Testnet).is_ok());
    }

    /// The check that has to exist before a vault holds real money: what the
    /// node says it is, against what we were told to expect.
    #[test]
    fn a_chain_mismatch_is_named_rather_than_papered_over() {
        let e = RpcError::WrongChain {
            want: "main",
            got: "test".into(),
        };
        let said = e.to_string();
        assert!(said.contains("test chain"), "{}", said);
        assert!(said.contains("configured for main"), "{}", said);
        // A node that answers with no chain at all is still a mismatch, and
        // says so without pretending to know what it is.
        let e = RpcError::WrongChain {
            want: "main",
            got: String::new(),
        };
        assert!(e.to_string().contains("unknown"), "{}", e);
    }

    /// The watcher asks for the balance at the height it is crediting, not at
    /// the tip. Answering with the tip's figure would attest backing for
    /// deposits the batch does not credit.
    #[test]
    fn a_balance_is_scoped_to_its_height() {
        let o = Observed::new(100, vec![dep(10, 1, 5), dep(20, 2, 7), dep(90, 3, 11)]);
        assert_eq!(o.balance_at(9), Some(Fixed::ZERO));
        assert_eq!(o.balance_at(10), Some(Fixed(5 * ZAT)));
        assert_eq!(o.balance_at(20), Some(Fixed(12 * ZAT)));
        assert_eq!(o.balance_at(100), Some(Fixed(23 * ZAT)));
        assert_eq!(
            o.balance_at(101),
            None,
            "a height past the tip is not knowable"
        );
    }

    #[test]
    fn deposits_are_returned_by_exact_height() {
        let o = Observed::new(50, vec![dep(10, 1, 5), dep(10, 2, 6), dep(11, 3, 7)]);
        assert_eq!(o.deposits_at(10).len(), 2);
        assert_eq!(o.deposits_at(11).len(), 1);
        assert!(
            o.deposits_at(12).is_empty(),
            "an empty height is empty, not an error"
        );
    }

    /// The snapshot has to drive the real watcher, not merely look like it
    /// could.
    #[test]
    fn the_watcher_runs_against_a_snapshot() {
        use crate::watcher::{Watcher, WatcherAction};
        let o = Observed::new(20, vec![dep(5, 1, 100), dep(6, 2, 250)]);
        let mut w = Watcher::new(6, 1);
        let actions = w.poll(&o).expect("poll");

        assert!(
            matches!(actions[0], WatcherAction::Attest { .. }),
            "attest comes first"
        );
        assert_eq!(actions.len(), 3, "one attestation and two credits");
        // Polling again sees nothing new — the deposits are already credited.
        assert!(w.poll(&o).expect("second poll").is_empty());
    }

    #[test]
    fn hex_decoding_refuses_what_it_cannot_read() {
        assert_eq!(unhex(""), Some(Vec::new()));
        assert_eq!(unhex("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(unhex("abc"), None, "odd length is not hex");
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn a_txid_must_be_thirty_two_bytes() {
        assert!(hex32("ab").is_none());
        assert!(hex32(&"zz".repeat(32)).is_none());
        assert_eq!(hex32(&"00".repeat(32)), Some([0u8; 32]));
    }

    #[test]
    fn basic_auth_encodes_as_rfc_4648() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
    }
}
