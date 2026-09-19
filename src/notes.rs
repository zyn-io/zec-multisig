//! What the vault holds, and how to prove it holds it.
//!
//! [`crate::shielded`] finds deposits. Spending one needs three things it does
//! not provide: the note's **position** in Orchard's commitment tree, an
//! **authentication path** from that position to a root, and an **anchor** —
//! a root the chain has actually seen.
//!
//! # Why a tree has to be maintained at all
//!
//! A note's authentication path changes every time anything is appended to the
//! tree, which is every shielded output on the network. It cannot be fetched
//! once and kept, and it cannot be recomputed from the note.
//!
//! The standard answer, and the one every Zcash wallet uses, is to hold a
//! *witnessing* tree: append every commitment in order, and retain the paths
//! only for the notes that are ours. `bridgetree` does exactly that and is
//! built for it — the alternative is storing 2³² nodes to answer questions
//! about a handful.
//!
//! # Where the tree starts
//!
//! Not at genesis. `z_gettreestate` gives the frontier at any height (verified
//! against a live node, `DECISIONS` §13a), so a vault starts from the frontier
//! at its birthday and appends from there. Everything before it is provably
//! not ours: the vault did not exist.

use std::collections::BTreeMap;

use bridgetree::BridgeTree;
use incrementalmerkletree::Position;
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::Note;

/// How many appends back a witness stays available.
///
/// A checkpoint is what lets the tree be rewound when a block is reorganised
/// away. Deep enough that a reorg cannot outrun it, shallow enough that the
/// retained state stays small — the same reasoning as a confirmation depth,
/// and it should be at least as large as one.
const CHECKPOINT_DEPTH: usize = 100;

/// Orchard's note commitment tree depth, fixed by the protocol.
///
/// Spelled out because `orchard` keeps its own copy private. It is a consensus
/// constant, so a mismatch would not be a compile error — it would be paths
/// that verify against nothing.
const DEPTH: u8 = 32;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeldNote {
    pub note: Note,
    /// Where its commitment sits in Orchard's tree.
    pub position: Position,
    /// Block it was mined at, for reporting and for reorg handling.
    pub height: u64,
    /// The transaction that paid it, as reported by the node.
    pub txid: [u8; 32],
}

impl HeldNote {
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NoteError {
    /// The tree has no witness at that position — it was never marked, or it
    /// has been pruned past.
    NoWitness,
    /// The tree is empty, so there is no anchor to spend against.
    NoAnchor,
    /// The vault does not hold enough to cover the amount.
    Insufficient { held: u64, needed: u64 },
    /// The node's tree state did not parse.
    BadFrontier,
}

/// The vault's spendable notes, and the tree that proves them.
pub struct NoteStore {
    tree: BridgeTree<MerkleHashOrchard, u32, DEPTH>,
    /// Ours, by position. Spending removes.
    held: BTreeMap<u64, HeldNote>,
    /// Spent by us and broadcast, not yet seen spent on the chain. Not
    /// spendable, not counted — but still *ours*, so the scanner recognises
    /// the transaction that spends them as one we sent and its change as
    /// change rather than as a deposit nobody can attribute. The chain's
    /// nullifier clears the entry.
    in_flight: BTreeMap<u64, HeldNote>,
    /// Nullifiers of our notes that the chain has shown spent. Kept so that
    /// a transaction can still be recognised as ours after its spend has
    /// been applied — two readers share this store (the settler feeds the
    /// tree to build an anchor, the deposit watcher classifies later), and
    /// the second must not mistake our own change for a stranger's deposit.
    spent: std::collections::BTreeSet<[u8; 32]>,
    /// Commitments appended so far, which is the next free position.
    appended: u64,
    /// The last block whose every commitment has been appended. A scan that
    /// re-reads a block — which it does, on any failure — must not append it
    /// twice, and this is what stops it.
    synced_to: Option<u64>,
}

impl Default for NoteStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteStore {
    pub fn new() -> NoteStore {
        NoteStore {
            tree: BridgeTree::new(CHECKPOINT_DEPTH),
            held: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            spent: Default::default(),
            appended: 0,
            synced_to: None,
        }
    }

    /// A store for a tree that does not exist yet: nothing appended, and
    /// every block up to `height` counted as seen. For a pool below its
    /// activation height.
    pub fn empty_at(height: u64) -> NoteStore {
        let mut s = NoteStore::new();
        s.synced_to = Some(height);
        s
    }

    /// A store that begins where the chain already is.
    ///
    /// `final_state` is the node's serialised frontier at some height
    /// (`Zebra::tree_state`). Every commitment before it is folded into the
    /// frontier — none can be witnessed, and the vault held none — and every
    /// commitment after it is appended by the scan. The root then equals the
    /// chain's, which `root_bytes` lets a caller check against the node.
    pub fn from_frontier(final_state: &[u8], height: u64) -> Result<NoteStore, NoteError> {
        let tree =
            zcash_primitives::merkle_tree::read_commitment_tree::<MerkleHashOrchard, _, DEPTH>(
                final_state,
            )
            .map_err(|_| NoteError::BadFrontier)?;
        let frontier = tree.to_frontier();
        let appended = frontier
            .value()
            .map(|f| u64::from(f.position()) + 1)
            .unwrap_or(0);
        let tree = match frontier.take() {
            Some(f) => BridgeTree::from_frontier(CHECKPOINT_DEPTH, f),
            None => BridgeTree::new(CHECKPOINT_DEPTH),
        };
        Ok(NoteStore {
            tree,
            held: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            spent: Default::default(),
            appended,
            synced_to: Some(height),
        })
    }

    /// The current root, in `MerkleHashOrchard` byte order.
    pub fn root_bytes(&self) -> Option<[u8; 32]> {
        self.tree.root(0).map(|h| h.to_bytes())
    }

    pub fn synced_to(&self) -> Option<u64> {
        self.synced_to
    }

    /// Every commitment in `height` is in. Blocks at or below this are skipped
    /// by a scan rather than appended again.
    pub fn finish_block(&mut self, height: u64) {
        self.synced_to = Some(height);
    }

    pub fn appended(&self) -> u64 {
        self.appended
    }

    /// Append one commitment from the chain, in order.
    ///
    /// **Every** Orchard commitment must be appended, not only ours: a note's
    /// path is its position among all of them, so a skipped commitment moves
    /// every later note and silently invalidates every path after it.
    ///
    /// `ours` marks the position for retention. Marking everything would work
    /// and would grow without limit, which is the cost `bridgetree` exists to
    /// avoid.
    pub fn append(&mut self, cmx: &ExtractedNoteCommitment, ours: bool) -> Option<Position> {
        if !self.tree.append(MerkleHashOrchard::from_cmx(cmx)) {
            return None; // the tree is full: 2^32 commitments
        }
        self.appended += 1;
        // Marking retains the path for the leaf just appended. Only ours, or
        // the retained state grows with the whole chain rather than with the
        // vault.
        if ours {
            self.tree.mark()
        } else {
            None
        }
    }

    /// Record a note we decrypted at a position we appended.
    pub fn hold(&mut self, note: Note, position: Position, height: u64, txid: [u8; 32]) {
        self.held.insert(
            position.into(),
            HeldNote {
                note,
                position,
                height,
                txid,
            },
        );
    }

    /// Mark the **start** of a block, before appending any of its
    /// commitments.
    ///
    /// Before, not after, and the distinction is load-bearing. `bridgetree`
    /// rewinds to the state a checkpoint was *taken at*, so a checkpoint
    /// recorded after a block restores that block rather than undoing it —
    /// measured, not assumed: two appends with a checkpoint after each needed
    /// **two** rewinds to undo one. Marking the start makes one rewind undo
    /// one block, which is the only thing a reorg ever asks for.
    pub fn begin_block(&mut self, height: u64) {
        self.tree.checkpoint(height as u32);
    }

    /// Undo the most recent block. Returns false if there is nothing to undo.
    pub fn rewind(&mut self) -> bool {
        if !self.tree.rewind() {
            return false;
        }
        // Notes at positions the tree no longer has are gone with it. A note
        // credited from a block that was reorganised away is not a note.
        let live = self.tree.current_position().map(u64::from);
        match live {
            None => self.held.clear(),
            Some(max) => self.held.retain(|p, _| *p <= max),
        }
        self.appended = live.map(|m| m + 1).unwrap_or(0);
        true
    }

    /// The root to spend against.
    pub fn anchor(&self) -> Result<orchard::Anchor, NoteError> {
        self.tree
            .root(0)
            .map(orchard::Anchor::from)
            .ok_or(NoteError::NoAnchor)
    }

    /// The authentication path for one held note.
    pub fn witness(&self, position: Position) -> Result<MerklePath, NoteError> {
        let path = self
            .tree
            .witness(position, 0)
            .map_err(|_| NoteError::NoWitness)?;
        let auth: [MerkleHashOrchard; DEPTH as usize] =
            path.try_into().map_err(|_| NoteError::NoWitness)?;
        Ok(MerklePath::from_parts(u64::from(position) as u32, auth))
    }

    pub fn held(&self) -> impl Iterator<Item = &HeldNote> {
        self.held.values()
    }

    pub fn balance(&self) -> u64 {
        self.held.values().map(HeldNote::value).sum()
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Choose notes to cover `amount`.
    ///
    /// Largest first, which minimises the number of actions in a bundle — and
    /// an action is a proof, so it is the expensive unit. The alternative,
    /// smallest-first, keeps change tidy at the cost of a larger and slower
    /// transaction every time.
    pub fn select(&self, amount: u64) -> Result<Vec<HeldNote>, NoteError> {
        let mut candidates: Vec<&HeldNote> = self.held.values().collect();
        candidates.sort_by(|a, b| b.value().cmp(&a.value()).then(a.position.cmp(&b.position)));

        let mut chosen = Vec::new();
        let mut total = 0u64;
        for n in candidates {
            if total >= amount {
                break;
            }
            total = total.saturating_add(n.value());
            chosen.push(n.clone());
        }
        if total < amount {
            return Err(NoteError::Insufficient {
                held: total,
                needed: amount,
            });
        }
        Ok(chosen)
    }

    /// Forget a note that has been spent.
    /// Forget the held note whose nullifier this is, if any. A wallet learns
    /// its own spends this way — the chain reveals nullifiers, not notes.
    pub fn spend_nullifier(
        &mut self,
        nf: &orchard::note::Nullifier,
        fvk: &orchard::keys::FullViewingKey,
    ) -> Option<HeldNote> {
        let gone = if let Some(pos) = self
            .in_flight
            .values()
            .find(|h| h.note.nullifier(fvk) == *nf)
            .map(|h| h.position)
        {
            self.in_flight.remove(&u64::from(pos))
        } else {
            let pos = self
                .held
                .values()
                .find(|h| h.note.nullifier(fvk) == *nf)
                .map(|h| h.position)?;
            self.held.remove(&u64::from(pos))
        };
        if gone.is_some() {
            self.spent.insert(nf.to_bytes());
        }
        gone
    }

    /// Whether this nullifier is one of ours — a note held, spent by us and
    /// not yet seen on the chain, or already seen spent. In every case the
    /// transaction revealing it is one this wallet sent.
    pub fn holds_nullifier(
        &self,
        nf: &orchard::note::Nullifier,
        fvk: &orchard::keys::FullViewingKey,
    ) -> bool {
        self.spent.contains(&nf.to_bytes())
            || self
                .held
                .values()
                .chain(self.in_flight.values())
                .any(|h| h.note.nullifier(fvk) == *nf)
    }

    /// Forget a note we have just spent. It stays known as *in flight*
    /// until the chain shows its nullifier, so that the transaction spending
    /// it is still recognised as ours when it is scanned.
    pub fn spend(&mut self, position: Position) -> Option<HeldNote> {
        let h = self.held.remove(&u64::from(position))?;
        self.in_flight.insert(u64::from(position), h.clone());
        Some(h)
    }

    /// Notes spent by us that the chain has not yet shown spent.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Their value: what left the balance and is not yet final.
    pub fn in_flight_balance(&self) -> u64 {
        self.in_flight.values().map(HeldNote::value).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::note::{NoteVersion, RandomSeed, Rho};
    use orchard::value::NoteValue;

    pub(crate) fn note(seed: u8, value: u64) -> Note {
        let sk = SpendingKey::from_bytes([seed; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = seed;
            b
        })
        .unwrap();
        let rseed = RandomSeed::from_bytes([seed ^ 0xAA; 32], &rho).unwrap();
        Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V2,
        )
        .unwrap()
    }

    pub(crate) fn cmx(n: &Note) -> ExtractedNoteCommitment {
        ExtractedNoteCommitment::from(n.commitment())
    }

    /// A note's path must open the anchor. This is the property a bundle
    /// checks, and everything else here is in service of it.
    #[test]
    fn a_held_note_proves_against_the_anchor() {
        let mut s = NoteStore::new();
        // Other people's commitments before, between and after ours.
        for k in 1..=3u8 {
            s.append(&cmx(&note(k + 100, 1)), false);
        }
        let ours = note(7, 500);
        let pos = s.append(&cmx(&ours), true).expect("a marked position");
        for k in 1..=5u8 {
            s.append(&cmx(&note(k + 120, 1)), false);
        }
        // (blocks are opened before their commitments; see `begin_block`)

        let anchor = s.anchor().expect("an anchor");
        let path = s.witness(pos).expect("a witness");
        assert_eq!(
            path.root(cmx(&ours)),
            anchor,
            "the note's path did not open the tree's root"
        );
    }

    /// Skipping a commitment moves every note after it. This is the mistake
    /// that produces paths which verify against nothing.
    #[test]
    fn a_skipped_commitment_invalidates_later_paths() {
        let build = |skip: bool| {
            let mut s = NoteStore::new();
            s.append(&cmx(&note(200, 1)), false);
            if !skip {
                s.append(&cmx(&note(201, 1)), false);
            }
            let ours = note(9, 42);
            let pos = s.append(&cmx(&ours), true).unwrap();
            (s, pos, ours)
        };
        let (complete, p1, n1) = build(false);
        let (skipped, p2, _) = build(true);
        assert_ne!(u64::from(p1), u64::from(p2), "the position did not move");
        // The complete tree's path opens its own root and not the other's.
        let path = complete.witness(p1).unwrap();
        assert_eq!(path.root(cmx(&n1)), complete.anchor().unwrap());
        assert_ne!(complete.anchor().unwrap(), skipped.anchor().unwrap());
    }

    #[test]
    fn selection_covers_the_amount_with_the_fewest_actions() {
        let mut s = NoteStore::new();
        for (i, v) in [100u64, 50, 400, 25].iter().enumerate() {
            let n = note(i as u8 + 10, *v);
            let p = s.append(&cmx(&n), true).unwrap();
            s.hold(n, p, 1, [i as u8; 32]);
        }
        assert_eq!(s.balance(), 575);

        // 400 alone covers 300 — one action, not three.
        let chosen = s.select(300).expect("selection");
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].value(), 400);

        // 400 + 100 covers 450.
        let chosen = s.select(450).expect("selection");
        assert_eq!(chosen.iter().map(HeldNote::value).sum::<u64>(), 500);
        assert_eq!(chosen.len(), 2);
    }

    #[test]
    fn selection_refuses_rather_than_underpaying() {
        let mut s = NoteStore::new();
        let n = note(3, 10);
        let p = s.append(&cmx(&n), true).unwrap();
        s.hold(n, p, 1, [0u8; 32]);
        assert_eq!(
            s.select(99),
            Err(NoteError::Insufficient {
                held: 10,
                needed: 99
            })
        );
    }

    /// A note credited from a block that was reorganised away is not a note.
    #[test]
    fn a_rewind_drops_notes_from_the_undone_block() {
        let mut s = NoteStore::new();
        s.begin_block(1);
        let keep = note(1, 100);
        let kp = s.append(&cmx(&keep), true).unwrap();
        s.hold(keep, kp, 1, [1u8; 32]);

        s.begin_block(2);
        let doomed = note(2, 200);
        let dp = s.append(&cmx(&doomed), true).unwrap();
        s.hold(doomed, dp, 2, [2u8; 32]);
        assert_eq!(s.balance(), 300);

        assert!(s.rewind(), "the tree should undo one block");
        assert_eq!(s.balance(), 100, "a reorganised-away note survived");
        assert!(s.witness(kp).is_ok(), "the surviving note lost its witness");
    }

    /// An empty tree still has a root — the empty-tree root — and it is a
    /// perfectly real anchor that no note opens. Worth pinning: "no notes" and
    /// "no anchor" are different conditions, and confusing them would mean
    /// building a bundle against a root nothing can be proved into.
    #[test]
    fn an_empty_store_has_an_anchor_but_nothing_to_spend() {
        let s = NoteStore::new();
        assert!(s.anchor().is_ok(), "the empty tree has a root");
        assert!(s.is_empty());
        assert_eq!(s.balance(), 0);
        assert!(matches!(
            s.select(1),
            Err(NoteError::Insufficient { held: 0, needed: 1 })
        ));
    }

    /// An unmarked position is somebody else's note, and we cannot witness it.
    #[test]
    fn unmarked_positions_are_not_witnessable() {
        let mut s = NoteStore::new();
        s.begin_block(1);
        s.append(&cmx(&note(50, 1)), false);
        assert!(matches!(
            s.witness(Position::from(0)),
            Err(NoteError::NoWitness)
        ));
    }
}

// ------------------------------------------------------------------ disk

/// Serialisation of the whole store, so a restart resumes where it stopped
/// instead of re-reading the chain from the vault's first block.
///
/// `bridgetree` has no serialiser of its own; its parts are all reachable, so
/// this writes them down field by field. The format is versioned and
/// length-checked, and a store that does not decode is a store that is
/// re-seeded from the node — never one that is half-trusted.
mod disk {
    use super::*;
    use bridgetree::{Checkpoint, MerkleBridge};
    use incrementalmerkletree::{Address, Level};
    use orchard::note::{NoteVersion, RandomSeed, Rho};
    use orchard::value::NoteValue;

    const MAGIC: &[u8; 8] = b"ZECNOTE1";

    struct W(Vec<u8>);
    impl W {
        fn u8(&mut self, v: u8) {
            self.0.push(v);
        }
        fn u32(&mut self, v: u32) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn u64(&mut self, v: u64) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn bytes(&mut self, b: &[u8]) {
            self.0.extend_from_slice(b);
        }
        fn hash(&mut self, h: &MerkleHashOrchard) {
            self.bytes(&h.to_bytes());
        }
        fn opt_u64(&mut self, v: Option<u64>) {
            self.u8(v.is_some() as u8);
            self.u64(v.unwrap_or(0));
        }
        fn address(&mut self, a: &Address) {
            self.u8(u8::from(a.level()));
            self.u64(a.index());
        }
        fn frontier(
            &mut self,
            f: &incrementalmerkletree::frontier::NonEmptyFrontier<MerkleHashOrchard>,
        ) {
            self.u64(u64::from(f.position()));
            self.hash(f.leaf());
            self.u32(f.ommers().len() as u32);
            for o in f.ommers() {
                self.hash(o);
            }
        }
        fn bridge(&mut self, b: &MerkleBridge<MerkleHashOrchard>) {
            self.opt_u64(b.prior_position().map(u64::from));
            self.u32(b.tracking().len() as u32);
            for a in b.tracking() {
                self.address(a);
            }
            self.u32(b.ommers().len() as u32);
            for (a, h) in b.ommers() {
                self.address(a);
                self.hash(h);
            }
            self.frontier(b.frontier());
        }
    }

    struct R<'a>(&'a [u8], usize);
    impl<'a> R<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let s = self.0.get(self.1..self.1 + n)?;
            self.1 += n;
            Some(s)
        }
        fn u8(&mut self) -> Option<u8> {
            Some(self.take(1)?[0])
        }
        fn u32(&mut self) -> Option<u32> {
            Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
        }
        fn u64(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
        }
        fn arr32(&mut self) -> Option<[u8; 32]> {
            self.take(32)?.try_into().ok()
        }
        fn hash(&mut self) -> Option<MerkleHashOrchard> {
            Option::from(MerkleHashOrchard::from_bytes(&self.arr32()?))
        }
        fn opt_u64(&mut self) -> Option<Option<u64>> {
            let has = self.u8()? != 0;
            let v = self.u64()?;
            Some(has.then_some(v))
        }
        fn address(&mut self) -> Option<Address> {
            let l = self.u8()?;
            let i = self.u64()?;
            Some(Address::from_parts(Level::from(l), i))
        }
        fn frontier(
            &mut self,
        ) -> Option<incrementalmerkletree::frontier::NonEmptyFrontier<MerkleHashOrchard>> {
            let pos = Position::from(self.u64()?);
            let leaf = self.hash()?;
            let n = self.u32()? as usize;
            let mut ommers = Vec::with_capacity(n);
            for _ in 0..n {
                ommers.push(self.hash()?);
            }
            incrementalmerkletree::frontier::NonEmptyFrontier::from_parts(pos, leaf, ommers).ok()
        }
        fn bridge(&mut self) -> Option<MerkleBridge<MerkleHashOrchard>> {
            let prior = self.opt_u64()?.map(Position::from);
            let n = self.u32()? as usize;
            let mut tracking = std::collections::BTreeSet::new();
            for _ in 0..n {
                tracking.insert(self.address()?);
            }
            let n = self.u32()? as usize;
            let mut ommers = BTreeMap::new();
            for _ in 0..n {
                let a = self.address()?;
                ommers.insert(a, self.hash()?);
            }
            let frontier = self.frontier()?;
            Some(MerkleBridge::from_parts(prior, tracking, ommers, frontier))
        }
    }

    impl W {
        fn held(&mut self, h: &HeldNote) {
            self.u64(u64::from(h.position));
            self.u64(h.height);
            self.bytes(&h.txid);
            self.bytes(&h.note.recipient().to_raw_address_bytes());
            self.u64(h.note.value().inner());
            self.bytes(&h.note.rho().to_bytes());
            self.bytes(h.note.rseed().as_bytes());
            self.u8(match h.note.version() {
                NoteVersion::V2 => 2,
                _ => 3,
            });
        }
    }

    impl R<'_> {
        fn held(&mut self) -> Option<HeldNote> {
            let position = Position::from(self.u64()?);
            let height = self.u64()?;
            let txid = self.arr32()?;
            let raw: [u8; 43] = self.take(43)?.try_into().ok()?;
            let recipient: Option<orchard::Address> =
                orchard::Address::from_raw_address_bytes(&raw).into();
            let value = NoteValue::from_raw(self.u64()?);
            let rho: Option<Rho> = Rho::from_bytes(&self.arr32()?).into();
            let rho = rho?;
            let rseed: Option<RandomSeed> = RandomSeed::from_bytes(self.arr32()?, &rho).into();
            let version = match self.u8()? {
                2 => NoteVersion::V2,
                3 => NoteVersion::V3,
                _ => return None,
            };
            let note: Option<Note> =
                Note::from_parts(recipient?, value, rho, rseed?, version).into();
            Some(HeldNote {
                note: note?,
                position,
                height,
                txid,
            })
        }
    }

    impl NoteStore {
        pub fn encode(&self) -> Vec<u8> {
            let mut w = W(Vec::new());
            w.bytes(MAGIC);
            w.u64(self.appended);
            w.opt_u64(self.synced_to);
            let t = &self.tree;
            w.u32(t.max_checkpoints() as u32);
            w.u32(t.prior_bridges().len() as u32);
            for b in t.prior_bridges() {
                w.bridge(b);
            }
            w.u8(t.current_bridge().is_some() as u8);
            if let Some(b) = t.current_bridge() {
                w.bridge(b);
            }
            w.u32(t.marked_indices().len() as u32);
            for (p, i) in t.marked_indices() {
                w.u64(u64::from(*p));
                w.u64(*i as u64);
            }
            w.u32(t.checkpoints().len() as u32);
            for c in t.checkpoints() {
                w.u32(*c.id());
                w.u64(c.bridges_len() as u64);
                w.u32(c.marked().len() as u32);
                for p in c.marked() {
                    w.u64(u64::from(*p));
                }
                w.u32(c.forgotten().len() as u32);
                for p in c.forgotten() {
                    w.u64(u64::from(*p));
                }
            }
            w.u32(self.held.len() as u32);
            for h in self.held.values() {
                w.held(h);
            }
            // Appended after the original layout, so a file written before
            // in-flight notes existed still reads (as having none).
            w.u32(self.in_flight.len() as u32);
            for h in self.in_flight.values() {
                w.held(h);
            }
            w.u32(self.spent.len() as u32);
            for nf in &self.spent {
                w.bytes(nf);
            }
            w.0
        }

        pub fn decode(buf: &[u8]) -> Option<NoteStore> {
            let mut r = R(buf, 0);
            if r.take(8)? != MAGIC {
                return None;
            }
            let appended = r.u64()?;
            let synced_to = r.opt_u64()?;
            let max_checkpoints = r.u32()? as usize;
            let n = r.u32()? as usize;
            let mut prior = Vec::with_capacity(n);
            for _ in 0..n {
                prior.push(r.bridge()?);
            }
            let current = if r.u8()? != 0 {
                Some(r.bridge()?)
            } else {
                None
            };
            let n = r.u32()? as usize;
            let mut saved = BTreeMap::new();
            for _ in 0..n {
                let p = Position::from(r.u64()?);
                saved.insert(p, r.u64()? as usize);
            }
            let n = r.u32()? as usize;
            let mut checkpoints = std::collections::VecDeque::with_capacity(n);
            for _ in 0..n {
                let id = r.u32()?;
                let bridges_len = r.u64()? as usize;
                let m = r.u32()? as usize;
                let mut marked = std::collections::BTreeSet::new();
                for _ in 0..m {
                    marked.insert(Position::from(r.u64()?));
                }
                let m = r.u32()? as usize;
                let mut forgotten = std::collections::BTreeSet::new();
                for _ in 0..m {
                    forgotten.insert(Position::from(r.u64()?));
                }
                checkpoints.push_back(Checkpoint::from_parts(id, bridges_len, marked, forgotten));
            }
            let tree =
                BridgeTree::from_parts(prior, current, saved, checkpoints, max_checkpoints).ok()?;
            let n = r.u32()? as usize;
            let mut held = BTreeMap::new();
            for _ in 0..n {
                let h = r.held()?;
                held.insert(u64::from(h.position), h);
            }
            let mut in_flight = BTreeMap::new();
            let mut spent = std::collections::BTreeSet::new();
            if r.1 != buf.len() {
                let n = r.u32()? as usize;
                for _ in 0..n {
                    let h = r.held()?;
                    in_flight.insert(u64::from(h.position), h);
                }
            }
            if r.1 != buf.len() {
                let n = r.u32()? as usize;
                for _ in 0..n {
                    spent.insert(r.arr32()?);
                }
            }
            if r.1 != buf.len() {
                return None;
            }
            Some(NoteStore {
                tree,
                held,
                in_flight,
                spent,
                appended,
                synced_to,
            })
        }
    }
}

#[cfg(test)]
mod disk_tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::note::{NoteVersion, RandomSeed, Rho};
    use orchard::value::NoteValue;

    /// The bug this guards: the settler forgot a note at broadcast, the
    /// scanner then saw the settlement spend an unknown nullifier and took
    /// the vault's own change for an unattributable deposit — and stopped.
    #[test]
    fn a_note_spent_by_us_stays_ours_until_the_chain_says_so() {
        let sk = SpendingKey::from_bytes([3u8; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let addr = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        let note: Option<Note> = Note::from_parts(
            addr,
            NoteValue::from_raw(5_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .into();
        let note = note.unwrap();
        let nf = note.nullifier(&fvk);

        let mut s = NoteStore::new();
        let pos = s.append(&note.commitment().into(), true).unwrap();
        s.hold(note, pos, 10, [9u8; 32]);
        assert_eq!(s.balance(), 5_000);

        // We spend it: gone from the balance, still ours.
        assert!(s.spend(pos).is_some());
        assert_eq!(s.balance(), 0);
        assert_eq!(s.in_flight(), 1);
        assert!(
            s.holds_nullifier(&nf, &fvk),
            "the scanner must still recognise our own spend"
        );

        // Across a restart, too.
        let mut s = NoteStore::decode(&s.encode()).expect("round trip");
        assert!(s.holds_nullifier(&nf, &fvk));

        // The chain shows the nullifier: the note is gone, but the nullifier
        // stays known as ours — a second reader of this store classifying
        // the same block must still see the spend as our own.
        assert!(s.spend_nullifier(&nf, &fvk).is_some());
        assert!(
            s.holds_nullifier(&nf, &fvk),
            "a spent nullifier must still read as ours"
        );
        assert_eq!(s.in_flight(), 0);
        assert_eq!(s.balance(), 0);
        let s = NoteStore::decode(&s.encode()).unwrap();
        assert_eq!(s.in_flight(), 0);
        assert!(
            s.holds_nullifier(&nf, &fvk),
            "and that memory survives a save"
        );
    }

    fn note(seed: u8, to: orchard::Address, version: NoteVersion) -> Note {
        // Small integers are always valid field elements; a repeated byte is not.
        let mut r = [0u8; 32];
        r[0] = seed;
        r[1] = 1;
        let rho = Rho::from_bytes(&r).unwrap();
        let mut rs = [0u8; 32];
        rs[0] = seed;
        rs[2] = 1;
        let rseed = (0u8..=255)
            .find_map(|k| {
                rs[3] = k;
                Option::<RandomSeed>::from(RandomSeed::from_bytes(rs, &rho))
            })
            .unwrap();
        Note::from_parts(
            to,
            NoteValue::from_raw(1000 + seed as u64),
            rho,
            rseed,
            version,
        )
        .unwrap()
    }

    /// The property that matters: a store written to disk and read back
    /// yields the same root and the same witnesses, and keeps yielding them
    /// as the chain goes on — so a restart is invisible to a later spend.
    #[test]
    fn a_store_survives_disk_and_keeps_witnessing() {
        let fvk = FullViewingKey::from(&SpendingKey::from_bytes([1u8; 32]).unwrap());
        let ours = fvk.address_at(0u32, Scope::External);
        let theirs = FullViewingKey::from(&SpendingKey::from_bytes([2u8; 32]).unwrap())
            .address_at(0u32, Scope::External);
        let mut a = NoteStore::new();
        let mut held_pos = Vec::new();
        for h in 1..=40u64 {
            a.begin_block(h);
            for k in 0..3u8 {
                let mine = (h % 7 == 0) && k == 1;
                let n = note(
                    (h as u8) * 3 + k,
                    if mine { ours } else { theirs },
                    NoteVersion::V3,
                );
                let pos = a.append(&ExtractedNoteCommitment::from(n.commitment()), mine);
                if mine {
                    let pos = pos.expect("marked");
                    a.hold(n, pos, h, [h as u8; 32]);
                    held_pos.push(pos);
                }
            }
            a.finish_block(h);
        }
        let bytes = a.encode();
        let mut b = NoteStore::decode(&bytes).expect("decodes");
        assert_eq!(b.root_bytes(), a.root_bytes());
        assert_eq!(b.synced_to(), Some(40));
        assert_eq!(b.balance(), a.balance());
        for p in &held_pos {
            assert_eq!(
                b.witness(*p).unwrap().auth_path().to_vec(),
                a.witness(*p).unwrap().auth_path().to_vec()
            );
        }
        // Keep going on both; they must stay identical.
        for h in 41..=60u64 {
            for s in [&mut a, &mut b] {
                s.begin_block(h);
                let n = note((h as u8) * 3, theirs, NoteVersion::V3);
                s.append(&ExtractedNoteCommitment::from(n.commitment()), false);
                s.finish_block(h);
            }
        }
        assert_eq!(b.root_bytes(), a.root_bytes());
        for p in &held_pos {
            assert_eq!(
                b.witness(*p).unwrap().auth_path().to_vec(),
                a.witness(*p).unwrap().auth_path().to_vec()
            );
        }
        // Junk is not a store.
        assert!(NoteStore::decode(&bytes[..bytes.len() - 1]).is_none());
        assert!(NoteStore::decode(b"ZECNOTE1junk").is_none());
    }
}
