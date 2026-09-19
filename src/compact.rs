//! Compact blocks: what a wallet needs to find its notes without seeing
//! everything else.
//!
//! Trial decryption needs, per shielded output, the nullifier, the note
//! commitment, the ephemeral key and the first 52 bytes of the ciphertext.
//! A block boiled down to that is a few hundred bytes instead of tens of
//! kilobytes, and a wallet can scan a year of it in minutes on a laptop —
//! which is the lightwalletd idea. This is the same idea, in Rust, over
//! Zebra, for **both** shielded pools: lightwalletd's format has no place for
//! Ironwood actions and its parser predates v6 transactions, so post-NU6.3
//! it cannot be the wallet's source of truth.
//!
//! The wallet fetches the full transaction only for the outputs that
//! decrypt, to read the memo — so the server learns which transactions a
//! wallet asked for, never which addresses it holds. Same trade lightwalletd
//! makes; stated rather than assumed.

use orchard::keys::PreparedIncomingViewingKey;
use orchard::note::{ExtractedNoteCommitment, Nullifier};
use orchard::note_encryption::{CompactAction, IronwoodDomain, OrchardDomain};
use orchard::ValuePool;
use zcash_note_encryption::{try_compact_note_decryption, EphemeralKeyBytes};
use zcash_primitives::block::Block;
use zcash_primitives::transaction::Transaction;

/// One shielded output, as much of it as trial decryption needs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompactOutput {
    pub nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub epk: [u8; 32],
    pub ciphertext: [u8; 52],
}

impl CompactOutput {
    pub fn to_action(&self) -> Option<CompactAction> {
        let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&self.nullifier))?;
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
            &self.cmx,
        ))?;
        Some(CompactAction::from_parts(
            nf,
            cmx,
            EphemeralKeyBytes(self.epk),
            self.ciphertext,
        ))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompactTx {
    /// Position in the block.
    pub index: u32,
    /// As the chain commits to it (little-endian), not as displayed.
    pub txid: [u8; 32],
    pub orchard: Vec<CompactOutput>,
    pub ironwood: Vec<CompactOutput>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompactBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub txs: Vec<CompactTx>,
}

fn outputs<A: orchard::bundle::Authorization>(
    b: &orchard::Bundle<A, zcash_protocol::value::ZatBalance>,
) -> Vec<CompactOutput> {
    b.actions()
        .iter()
        .map(|a| {
            let mut ciphertext = [0u8; 52];
            ciphertext.copy_from_slice(&a.encrypted_note().enc_ciphertext[..52]);
            CompactOutput {
                nullifier: a.nullifier().to_bytes(),
                cmx: a.cmx().to_bytes(),
                epk: a.encrypted_note().epk_bytes,
                ciphertext,
            }
        })
        .collect()
}

impl CompactTx {
    pub fn from_transaction(index: u32, tx: &Transaction) -> CompactTx {
        CompactTx {
            index,
            txid: *tx.txid().as_ref(),
            orchard: tx.orchard_bundle().map(outputs).unwrap_or_default(),
            ironwood: tx.ironwood_bundle().map(outputs).unwrap_or_default(),
        }
    }
}

impl CompactBlock {
    /// Every shielded transaction in the block; the rest are left out — a
    /// wallet has nothing to look for in them.
    pub fn from_block(height: u64, block: &Block) -> CompactBlock {
        let txs = block
            .vtx()
            .iter()
            .enumerate()
            .map(|(i, tx)| CompactTx::from_transaction(i as u32, tx))
            .filter(|t| !t.orchard.is_empty() || !t.ironwood.is_empty())
            .collect();
        CompactBlock {
            height,
            hash: block.header().hash().0,
            txs,
        }
    }

    // --- a fixed binary form, so a cache file and a wire frame are the same bytes ---

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(b"ZECCB1");
        o.extend_from_slice(&self.height.to_le_bytes());
        o.extend_from_slice(&self.hash);
        o.extend_from_slice(&(self.txs.len() as u32).to_le_bytes());
        for t in &self.txs {
            o.extend_from_slice(&t.index.to_le_bytes());
            o.extend_from_slice(&t.txid);
            for list in [&t.orchard, &t.ironwood] {
                o.extend_from_slice(&(list.len() as u32).to_le_bytes());
                for c in list {
                    o.extend_from_slice(&c.nullifier);
                    o.extend_from_slice(&c.cmx);
                    o.extend_from_slice(&c.epk);
                    o.extend_from_slice(&c.ciphertext);
                }
            }
        }
        o
    }

    pub fn decode(b: &[u8]) -> Option<CompactBlock> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = b.get(p..p + n)?;
            p += n;
            Some(s)
        };
        if take(6)? != b"ZECCB1" {
            return None;
        }
        let height = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let hash: [u8; 32] = take(32)?.try_into().ok()?;
        let n = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            let index = u32::from_le_bytes(take(4)?.try_into().ok()?);
            let txid: [u8; 32] = take(32)?.try_into().ok()?;
            let mut lists = [Vec::new(), Vec::new()];
            for list in lists.iter_mut() {
                let m = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
                for _ in 0..m {
                    list.push(CompactOutput {
                        nullifier: take(32)?.try_into().ok()?,
                        cmx: take(32)?.try_into().ok()?,
                        epk: take(32)?.try_into().ok()?,
                        ciphertext: take(52)?.try_into().ok()?,
                    });
                }
            }
            let [orchard, ironwood] = lists;
            txs.push(CompactTx {
                index,
                txid,
                orchard,
                ironwood,
            });
        }
        if p != b.len() {
            return None;
        }
        Some(CompactBlock { height, hash, txs })
    }
}

/// An output that decrypted: where it is, so the full transaction can be
/// fetched for the memo and the note held.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hit {
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub pool: ValuePool,
    pub action: usize,
    pub cmx: [u8; 32],
    pub value: u64,
}

/// Trial-decrypt every output in the block with one incoming viewing key.
pub fn scan(block: &CompactBlock, ivk: &PreparedIncomingViewingKey) -> Vec<Hit> {
    let mut hits = Vec::new();
    for t in &block.txs {
        for (pool, list) in [
            (ValuePool::Orchard, &t.orchard),
            (ValuePool::Ironwood, &t.ironwood),
        ] {
            for (i, out) in list.iter().enumerate() {
                let Some(act) = out.to_action() else { continue };
                let value = match pool {
                    ValuePool::Orchard => try_compact_note_decryption(
                        &OrchardDomain::for_compact_action(&act),
                        ivk,
                        &act,
                    )
                    .map(|(n, _)| n.value().inner()),
                    ValuePool::Ironwood => try_compact_note_decryption(
                        &IronwoodDomain::for_compact_action(&act),
                        ivk,
                        &act,
                    )
                    .map(|(n, _)| n.value().inner()),
                };
                if let Some(value) = value {
                    hits.push(Hit {
                        tx_index: t.index,
                        txid: t.txid,
                        pool,
                        action: i,
                        cmx: out.cmx,
                        value,
                    });
                }
            }
        }
    }
    hits
}
