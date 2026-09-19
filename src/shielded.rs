//! Seeing a shielded deposit.
//!
//! This is the layer the transparent scaffold in [`crate::zebra`] stands in
//! for, and the one this is built for: a depositor sends **shielded** ZEC
//! to the vault with a memo naming their account, and nothing about the
//! transaction is public.
//!
//! A shielded output says nothing to an observer. Finding ours means trial
//! decryption: for every Orchard action in every transaction, attempt
//! decryption with the vault's incoming viewing key, and keep the ones that
//! succeed. Failure is the overwhelmingly common case and is not an error.
//!
//! # Which key does what
//!
//! An Orchard full viewing key is `(ak, nk, rivk)`. Only `ak` — the spend
//! *authorization* key — is what FROST threshold-signs, because RedPallas is
//! the scheme Orchard uses for spend authorisation and nothing else.
//!
//! That has a consequence worth stating plainly, because it is easy to assume
//! the DKG produces everything: **`nk` and `rivk` are not produced by the
//! ceremony and must come from somewhere else.** They grant *viewing*, never
//! spending, so they can be held by every signer and by the watcher without
//! weakening custody — but they have to be generated once, deliberately, and
//! distributed alongside the shares. A signer set that ran a DKG and stopped
//! has a key that can authorise a spend and no way to find what to spend.
//!
//! # What this does not do
//!
//! It finds deposits. It cannot spend them — that needs note commitment tree
//! witnesses, a proof, and a bundle, none of which live here. Detection and
//! payout are separate problems and only the first is solved.

use alloc_std::collections::BTreeMap;
use alloc_std::string::String;
use alloc_std::vec::Vec;

use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
use orchard::note_encryption::{IronwoodDomain, OrchardDomain};
use orchard::ValuePool;
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;
use zcash_protocol::consensus::NetworkType;
use crate::amount::Fixed;

use crate::memo;
use crate::notes::NoteStore;
use crate::watcher::ObservedDeposit;
use orchard::note::ExtractedNoteCommitment;
use orchard::Note;
use std::sync::{Arc, Mutex};
use crate::account::AccountId;

mod alloc_std {
    pub use std::{collections, string, vec};
}

/// One zatoshi in `Fixed`'s 1e18 scale.
const ZAT: i128 = 10_000_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum ScanError {
    /// The bytes were not a transaction this consensus branch can read.
    Undecodable,
    /// A note decrypted, but its memo was not a deposit memo.
    ///
    /// Reported rather than skipped: someone sent the vault shielded funds
    /// without saying who they are for, which is a real deposit that cannot be
    /// credited and needs a human.
    UnaddressedDeposit(Fixed),
}

/// What the watcher needs in order to see, and nothing it needs in order to
/// spend.
#[derive(Clone)]
pub struct VaultKeys {
    fvk: FullViewingKey,
    ivk: PreparedIncomingViewingKey,
    /// The same key unprepared, which is the only form that can recover a
    /// diversifier index from an address.
    plain_ivk: orchard::keys::IncomingViewingKey,
}

impl VaultKeys {
    /// Derive from a whole spending key.
    ///
    /// For testnet and for tests. In production the spending authority is
    /// split by FROST and never exists in one place — see the module docs for
    /// what that leaves the viewing key needing.
    pub fn from_spending_key(bytes: [u8; 32]) -> Option<VaultKeys> {
        let sk: Option<SpendingKey> = SpendingKey::from_bytes(bytes).into();
        let fvk = FullViewingKey::from(&sk?);
        Some(VaultKeys::from_full_viewing_key(fvk))
    }

    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    pub fn from_full_viewing_key(fvk: FullViewingKey) -> VaultKeys {
        let plain = fvk.to_ivk(Scope::External);
        let ivk = PreparedIncomingViewingKey::new(&plain);
        VaultKeys {
            fvk,
            ivk,
            plain_ivk: plain,
        }
    }

    /// The address an account's deposits arrive at.
    ///
    /// One address per account, so a depositor needs no memo and no wallet
    /// feature — the address *is* the attribution. It is also what makes a
    /// credit checkable by someone other than the operator: the diversifier
    /// index is recoverable from the note, and [`deposit_index`] recomputes it
    /// from the account the credit names.
    pub fn deposit_address(&self, account: &AccountId, network: NetworkType) -> String {
        self.encode_address(
            self.fvk.address_at(deposit_index(account), Scope::External),
            network,
        )
    }

    /// The diversifier index a note arrived at, if this key can tell.
    ///
    /// `Some(ZERO)` is the vault's own address: change, anchors, top-ups.
    /// Anything else is a deposit address handed to one account.
    pub fn index_of(&self, note: &Note) -> Option<[u8; 11]> {
        self.plain_ivk
            .diversifier_index(&note.recipient())
            .map(|i| *i.as_bytes())
    }

    /// A unified address to hand a depositor.
    ///
    /// Orchard-only on purpose. A unified address containing a Sapling
    /// receiver invites a sender to use it, and a Sapling note is one this
    /// scanner will not see — the failure would be silence, which is the worst
    /// shape a deposit failure can take.
    pub fn address(&self, index: u32, network: NetworkType) -> String {
        self.encode_address(self.fvk.address_at(index, Scope::External), network)
    }

    /// The network is a required argument, deliberately.
    ///
    /// A default here would be the wrong kind of convenience: the encoding is
    /// the only thing that distinguishes an address people can pay from one
    /// nobody can, and a forgotten argument would be invisible until a
    /// depositor's wallet refused the address. Make the compiler ask.
    fn encode_address(&self, addr: orchard::Address, network: NetworkType) -> String {
        use zcash_address::unified::{Address, Encoding, Receiver};
        let ua = Address::try_from_items(vec![Receiver::Orchard(addr.to_raw_address_bytes())])
            .expect("an orchard receiver is a valid unified address");
        ua.encode(&network)
    }

    /// Every deposit to this vault inside one transaction.
    ///
    /// `Ok(vec![])` is the normal answer: almost no transaction on the chain
    /// is ours, and that is not a failure.
    pub fn scan_transaction(
        &self,
        raw: &[u8],
        txid: [u8; 32],
        height: u64,
    ) -> Result<Vec<ObservedDeposit>, ScanError> {
        self.scan_actions(raw, txid, height).map(|s| s.deposits)
    }

    /// Every Orchard action in one transaction — ours decrypted, the rest as
    /// bare commitments — plus the deposits among ours.
    ///
    /// The tree a spend is proved against contains **every** commitment on
    /// the chain, not only the vault's, so a scan that only kept its own
    /// notes would hold notes it could never witness.
    pub fn scan_actions(
        &self,
        raw: &[u8],
        txid: [u8; 32],
        height: u64,
    ) -> Result<Scanned, ScanError> {
        self.scan_actions_with(raw, txid, height, &BTreeMap::new())
    }

    /// As [`scan_actions`](Self::scan_actions), but a note without a memo is
    /// simply ours — a wallet, not a vault, has no account to attribute it to.
    pub fn scan_actions_lenient(
        &self,
        raw: &[u8],
        txid: [u8; 32],
        height: u64,
    ) -> Result<Scanned, ScanError> {
        self.scan_inner(raw, txid, height, &BTreeMap::new(), true)
    }

    /// As [`scan_actions`](Self::scan_actions), with an operator's attributions
    /// for deposits that carry no memo (see [`Scanner::with_attributions`]).
    pub fn scan_actions_with(
        &self,
        raw: &[u8],
        txid: [u8; 32],
        height: u64,
        attributions: &BTreeMap<[u8; 32], AccountId>,
    ) -> Result<Scanned, ScanError> {
        self.scan_inner(raw, txid, height, attributions, false)
    }

    fn scan_inner(
        &self,
        raw: &[u8],
        txid: [u8; 32],
        height: u64,
        attributions: &BTreeMap<[u8; 32], AccountId>,
        lenient: bool,
    ) -> Result<Scanned, ScanError> {
        // The branch only matters for pre-v5 parsing; v5 and v6 carry their own.
        let tx = Transaction::read(raw, BranchId::Nu6_3).map_err(|_| ScanError::Undecodable)?;
        let mut out = Scanned::default();

        // Two pools since NU6.3, one viewing key. Ironwood is where wallets
        // now send; Orchard is where older ones and older deposits are. Each
        // has its own note-encryption domain and its own commitment tree.
        let mut output_index = 0u32;
        if let Some(bundle) = tx.orchard_bundle() {
            for action in bundle.actions() {
                let domain = OrchardDomain::for_action(action);
                let decrypted = try_note_decryption(&domain, &self.ivk, action);
                self.take(
                    &mut out,
                    ValuePool::Orchard,
                    *action.cmx(),
                    *action.nullifier(),
                    decrypted,
                    txid,
                    height,
                    output_index,
                    attributions,
                    lenient,
                )?;
                output_index = output_index.checked_add(1).ok_or(ScanError::Undecodable)?;
            }
        }
        if let Some(bundle) = tx.ironwood_bundle() {
            for action in bundle.actions() {
                let domain = IronwoodDomain::for_action(action);
                let decrypted = try_note_decryption(&domain, &self.ivk, action);
                self.take(
                    &mut out,
                    ValuePool::Ironwood,
                    *action.cmx(),
                    *action.nullifier(),
                    decrypted,
                    txid,
                    height,
                    output_index,
                    attributions,
                    lenient,
                )?;
                output_index = output_index.checked_add(1).ok_or(ScanError::Undecodable)?;
            }
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn take(
        &self,
        out: &mut Scanned,
        pool: ValuePool,
        cmx: ExtractedNoteCommitment,
        nullifier: orchard::note::Nullifier,
        decrypted: Option<(Note, orchard::Address, [u8; 512])>,
        txid: [u8; 32],
        height: u64,
        output_index: u32,
        attributions: &BTreeMap<[u8; 32], AccountId>,
        lenient: bool,
    ) -> Result<(), ScanError> {
        let Some((note, _addr, memo_bytes)) = decrypted else {
            out.actions.push(ScannedAction {
                pool,
                cmx,
                nullifier,
                ours: None,
                account: None,
                memo: None,
                to_index: None,
                anchor: false,
                forced: None,
                app_payment: None,
                app_reserved: false,
            });
            return Ok(()); // not ours, which is almost always the case
        };
        if memo::is_anchor(&memo_bytes) || memo::is_publication(&memo_bytes) {
            // The vault's own commitment — to a state root, or to a digest it is
            // publishing so the thing can be shown to predate a block. Money
            // only in the sense that a stamp is: recorded, never credited.
            out.actions.push(ScannedAction {
                pool,
                cmx,
                nullifier,
                to_index: self.index_of(&note),
                ours: Some(note),
                account: None,
                memo: Some(memo_bytes.to_vec()),
                anchor: true,
                forced: None,
                app_payment: None,
                app_reserved: false,
            });
            return Ok(());
        }
        let amount = Fixed(note.value().inner() as i128 * ZAT);
        if let Ok(payment) = memo::decode_app_payment(&memo_bytes) {
            out.app_payments.push(AppPaymentOutput {
                txid,
                height,
                output_index,
                amount,
                payment,
            });
            out.actions.push(ScannedAction {
                pool,
                cmx,
                nullifier,
                to_index: self.index_of(&note),
                ours: Some(note),
                account: None,
                memo: Some(memo_bytes.to_vec()),
                anchor: false,
                forced: None,
                app_payment: Some(payment),
                app_reserved: true,
            });
            return Ok(());
        }
        if memo::has_app_payment_tag(&memo_bytes) {
            if !lenient {
                return Err(ScanError::UnaddressedDeposit(amount));
            }
            out.actions.push(ScannedAction {
                pool,
                cmx,
                nullifier,
                to_index: self.index_of(&note),
                ours: Some(note),
                account: None,
                memo: Some(memo_bytes.to_vec()),
                anchor: false,
                forced: None,
                app_payment: None,
                app_reserved: true,
            });
            return Ok(());
        }
        if let Some(frame) = memo::forced_frame(&memo_bytes) {
            // A submission the sequencer's door refused. The note pays the
            // signer; the frame is the thing that must be applied. A scheme
            // the memo route cannot carry falls through as a memo-less note,
            // for a human to decide.
            if let Some(account) = memo::forced_account(frame) {
                out.deposits.push(ObservedDeposit {
                    txid,
                    account,
                    amount,
                    height,
                    asset: None,
                });
                out.forced.push(ForcedSighting {
                    txid,
                    height,
                    amount,
                    frame: frame.to_vec(),
                });
                out.actions.push(ScannedAction {
                    pool,
                    cmx,
                    nullifier,
                    to_index: self.index_of(&note),
                    ours: Some(note),
                    account: Some(account),
                    memo: Some(memo_bytes.to_vec()),
                    anchor: false,
                    forced: Some(frame.to_vec()),
                    app_payment: None,
                    app_reserved: false,
                });
                return Ok(());
            }
        }
        let account = match memo::decode(&memo_bytes) {
            Ok(account) => Some(account),
            // No usable memo. A human may already have said whose this is —
            // by txid, in writing — and otherwise it stops the scan: the
            // money is real and guessing its owner is the one thing not to do.
            Err(_) => match attributions.get(&txid) {
                Some(a) => Some(*a),
                None if lenient => None,
                None => return Err(ScanError::UnaddressedDeposit(amount)),
            },
        };
        if let Some(account) = account {
            out.deposits.push(ObservedDeposit {
                txid,
                account,
                amount,
                height,
                asset: None,
            });
        }
        out.actions.push(ScannedAction {
            pool,
            cmx,
            nullifier,
            to_index: self.index_of(&note),
            ours: Some(note),
            account,
            memo: Some(memo_bytes.to_vec()),
            anchor: false,
            forced: None,
            app_payment: None,
            app_reserved: false,
        });
        Ok(())
    }
}

/// Decide what a transaction's notes to us are.
///
/// - a memo naming an account is a deposit to it;
/// - no memo, in a transaction that **spends our own note**, is change from a
///   payout — held, never credited;
/// - no memo otherwise is a deposit only if a human attributed the txid, and
///   is refused (the amount, for the log) if not.
/// The diversifier index an account's deposits arrive at.
///
/// Domain-separated and deterministic, so anyone holding the viewing key can
/// recompute it from the account a credit names and check the note really
/// arrived there. That is what turns "the operator says this deposit is
/// Alice's" into something a verifier settles for itself.
///
/// Never index zero: that is the vault's own address, where change, anchors
/// and operator top-ups land. Keeping deposits off it is what lets a verifier
/// tell a stranger's money from the vault paying itself, with no note store
/// and no memo.
pub fn deposit_index(account: &AccountId) -> orchard::keys::DiversifierIndex {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"zec.deposit.index.v1");
    h.update(account);
    let d = h.finalize();
    let mut idx = [0u8; 11];
    idx.copy_from_slice(&d[..11]);
    if idx == [0u8; 11] {
        // Cannot happen twice in the life of the universe, and costs one byte
        // to rule out rather than reason about.
        idx[0] = 1;
    }
    orchard::keys::DiversifierIndex::from(idx)
}

/// The vault's own index: change, anchors, top-ups. Never a deposit.
pub const VAULT_INDEX: [u8; 11] = [0u8; 11];

pub fn classify(
    scanned: &Scanned,
    spends_ours: bool,
    attributed: Option<AccountId>,
    txid: [u8; 32],
    height: u64,
) -> Result<Vec<ObservedDeposit>, Fixed> {
    classify_addressed(
        scanned,
        spends_ours,
        attributed,
        txid,
        height,
        &BTreeMap::new(),
    )
}

/// [`classify`], knowing which deposit addresses have been handed out.
///
/// The address a note arrived at is the strongest signal there is: it was
/// derived for one account, it needs no cooperation from the sender, and a
/// verifier can recompute it. It is therefore tried first. A note at the
/// vault's own index falls through to the old order — memo, then change, then
/// the operator's attribution — so deposits made before per-account addresses
/// keep working.
pub fn classify_addressed(
    scanned: &Scanned,
    spends_ours: bool,
    attributed: Option<AccountId>,
    txid: [u8; 32],
    height: u64,
    handed_out: &BTreeMap<[u8; 11], AccountId>,
) -> Result<Vec<ObservedDeposit>, Fixed> {
    let mut out = Vec::new();
    for a in &scanned.actions {
        let Some(note) = &a.ours else { continue };
        if a.anchor || a.app_payment.is_some() {
            continue;
        }
        let amount = Fixed(note.value().inner() as i128 * ZAT);
        if a.app_reserved {
            return Err(amount);
        }
        // Arrived at an account's own deposit address: that settles it.
        if let Some(index) = a.to_index.filter(|i| *i != VAULT_INDEX) {
            if let Some(account) = handed_out.get(&index) {
                if *account != [0u8; 32] {
                    out.push(ObservedDeposit {
                        txid,
                        account: *account,
                        amount,
                        height,
                        asset: None,
                    });
                }
                continue;
            }
        }
        match (a.account, spends_ours, attributed) {
            // The all-zero account is nobody: a top-up of the vault by the
            // operator (to cover fees), held, never credited.
            (Some(account), _, _) if account == [0u8; 32] => {}
            (None, false, Some(account)) if account == [0u8; 32] => {}
            (Some(account), _, _) => out.push(ObservedDeposit {
                txid,
                account,
                amount,
                height,
                asset: None,
            }),
            (None, true, _) => {} // change
            (None, false, Some(account)) => out.push(ObservedDeposit {
                txid,
                account,
                amount,
                height,
                asset: None,
            }),
            (None, false, None) => return Err(amount),
        }
    }
    Ok(out)
}

/// One shielded action as the vault sees it, in whichever pool it sits.
pub struct ScannedAction {
    pub pool: ValuePool,
    pub cmx: ExtractedNoteCommitment,
    /// The nullifier this action reveals — a note somewhere was spent.
    pub nullifier: orchard::note::Nullifier,
    /// Decrypted, if it is ours.
    pub ours: Option<Note>,
    /// The account its memo names, if it names one.
    pub account: Option<AccountId>,
    /// The memo as decrypted, all 512 bytes, when the note is ours. A wallet
    /// shows it; the vault only reads the account out of it.
    pub memo: Option<Vec<u8>>,
    /// The diversifier index the note arrived at, when the key can recover
    /// it. Zero is the vault's own address; anything else is one account's
    /// deposit address, and says whose the money is without a memo.
    pub to_index: Option<[u8; 11]>,
    /// The note is the vault`s own self-send carrying a anchor
    /// (`memo::is_anchor`). Never a deposit, never change: evidence.
    pub anchor: bool,
    /// A signed submission the memo carried (`memo::forced_frame`). The note's
    /// value is a deposit to the signer; the frame is for the sequencer to
    /// apply and for a replica to hold it to.
    pub forced: Option<Vec<u8>>,
    /// A purpose-bound application payment. It is surfaced to the application
    /// and is never an
    /// ordinary account credit, even if it arrived at an issued address.
    pub app_payment: Option<memo::AppPaymentMemo>,
    /// The memo claimed the application namespace. If `app_payment` is absent it was
    /// malformed and classification fails instead of crediting by address.
    pub app_reserved: bool,
}

/// One purpose-bound application payment as seen in canonical transaction order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AppPaymentOutput {
    pub txid: [u8; 32],
    pub height: u64,
    /// Orchard actions first, followed by Ironwood actions, each in serialized
    /// bundle order. This makes a stable output coordinate within the txid.
    pub output_index: u32,
    pub amount: Fixed,
    pub payment: memo::AppPaymentMemo,
}

/// An application payment with its complete canonical position in a Zcash block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AppPaymentSighting {
    pub txid: [u8; 32],
    pub height: u64,
    pub tx_index: u32,
    pub output_index: u32,
    pub amount: Fixed,
    pub payment: memo::AppPaymentMemo,
}

/// One forced intent as seen on the chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ForcedSighting {
    pub txid: [u8; 32],
    pub height: u64,
    pub amount: Fixed,
    pub frame: Vec<u8>,
}

/// One anchor self-send as the vault sees it on the chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AnchorSighting {
    pub height: u64,
    pub txid: [u8; 32],
    /// The anchor memo, exactly `memo::ANCHOR_LEN` bytes.
    pub memo: [u8; memo::ANCHOR_LEN],
}

/// One transaction's actions and deposits.
#[derive(Default)]
pub struct Scanned {
    pub deposits: Vec<ObservedDeposit>,
    pub actions: Vec<ScannedAction>,
    /// Forced intents this transaction carried.
    pub forced: Vec<ForcedSighting>,
    /// Valid application payments, excluded from `deposits` by construction.
    pub app_payments: Vec<AppPaymentOutput>,
}

/// Scanning a range of blocks for deposits to this vault.
///
/// # Why this is bounded, and why it starts somewhere
///
/// Trial decryption costs one attempt per action in every transaction in every
/// block. Over a chain hundreds of thousands of blocks long that is not a slow
/// scan, it is one that never finishes — so a scan has a **floor** (the height
/// the vault was created at; nothing before it can be ours) and a **ceiling**
/// (how many blocks one pass will read).
///
/// Both are operational settings rather than a policy: the watcher makes no
/// progress on failure and the next pass repeats the same range, so a scan cut
/// short is resumed rather than lost.
pub struct Scanner {
    keys: VaultKeys,
    /// Never look below here. A vault cannot have been paid before it existed.
    from_height: u64,
    /// The most blocks one pass will read.
    max_blocks: u64,
    /// Blocks behind the tip the trees stop at. See [`Self::with_tree_lag`].
    tree_lag: u64,
    /// The note trees, one per pool, fed with every commitment the scan
    /// passes over. Shared with the settler, which witnesses spends against
    /// them. `None` for a deposit-only vault.
    notes: Option<PoolStores>,
    /// `txid -> account` for deposits that carry no memo, written by a human.
    attributions: BTreeMap<[u8; 32], AccountId>,
    /// `diversifier index -> account`: the deposit addresses handed out.
    /// Shared, because addresses are issued by the RPC while the scan runs.
    /// Nothing here is trusted — it says which account to credit, and a
    /// verifier rederives the index from that account and checks the note.
    addresses: Arc<Mutex<BTreeMap<[u8; 11], AccountId>>>,
}

/// The vault's two commitment trees.
#[derive(Clone)]
pub struct PoolStores {
    pub orchard: Arc<Mutex<NoteStore>>,
    pub ironwood: Arc<Mutex<NoteStore>>,
}

impl PoolStores {
    pub fn of(&self, pool: ValuePool) -> &Arc<Mutex<NoteStore>> {
        match pool {
            ValuePool::Orchard => &self.orchard,
            ValuePool::Ironwood => &self.ironwood,
        }
    }
    /// The lowest height both trees are complete to.
    pub fn synced_to(&self) -> Option<u64> {
        let a = self.orchard.lock().ok()?.synced_to()?;
        let b = self.ironwood.lock().ok()?.synced_to()?;
        Some(a.min(b))
    }
}

#[derive(Debug)]
pub enum ScanRangeError {
    Rpc(crate::zebra::RpcError),
    /// Shielded funds arrived that we can see and cannot attribute.
    ///
    /// Fatal to the pass on purpose. Crediting the rest and moving on would
    /// leave the vault holding money whose owner nobody recorded, and the
    /// backing attestation that follows would be wrong by exactly that amount.
    Unattributable {
        height: u64,
        amount: Fixed,
    },
}

impl From<crate::zebra::RpcError> for ScanRangeError {
    fn from(e: crate::zebra::RpcError) -> Self {
        ScanRangeError::Rpc(e)
    }
}

impl Scanner {
    /// Share a note tree with this scanner. Every commitment it passes over
    /// is appended, ours are held, and a block is appended once however many
    /// times it is re-read.
    pub fn with_notes(mut self, notes: PoolStores) -> Scanner {
        self.notes = Some(notes);
        self
    }

    /// Deposits without a memo that a human has assigned, by txid. The file
    /// is the audit trail; the scanner only reads it.
    pub fn with_attributions(mut self, attributions: BTreeMap<[u8; 32], AccountId>) -> Scanner {
        self.attributions = attributions;
        self
    }

    /// Share the register of deposit addresses that have been handed out.
    pub fn with_addresses(
        mut self,
        addresses: Arc<Mutex<BTreeMap<[u8; 11], AccountId>>>,
    ) -> Scanner {
        self.addresses = addresses;
        self
    }

    pub fn notes(&self) -> Option<&PoolStores> {
        self.notes.as_ref()
    }

    pub fn from_height(&self) -> u64 {
        self.from_height
    }

    pub fn new(keys: VaultKeys, from_height: u64, max_blocks: u64) -> Scanner {
        Scanner {
            keys,
            from_height,
            max_blocks: max_blocks.max(1),
            notes: None,
            attributions: BTreeMap::new(),
            addresses: Arc::new(Mutex::new(BTreeMap::new())),
            tree_lag: 0,
        }
    }

    /// Feed the note trees only with blocks at least this deep. A block at
    /// the tip can be reorganised away, and a tree that appended it names
    /// roots the chain never had — every witness built on it is refused. The
    /// deposit watcher applies the same depth before crediting; the tree
    /// must apply it before *believing*.
    pub fn with_tree_lag(mut self, blocks: u64) -> Scanner {
        self.tree_lag = blocks;
        self
    }

    pub fn address(&self, index: u32, network: NetworkType) -> String {
        self.keys.address(index, network)
    }

    /// Read the chain once and answer from the result.
    ///
    /// The returned snapshot reports a tip of the **last height actually
    /// scanned**, not the chain's real tip. That is deliberate: the watcher
    /// derives its safe height from the tip it is given, and telling it about
    /// blocks this pass never opened would let it mark them scanned.
    pub fn observe(
        &self,
        zebra: &crate::zebra::Zebra,
        from: u64,
    ) -> Result<crate::zebra::Observed, ScanRangeError> {
        let chain_tip = zebra.block_count()?;
        let start = from.max(self.from_height);
        let end = chain_tip.min(start.saturating_add(self.max_blocks).saturating_sub(1));
        if end < start {
            return Ok(crate::zebra::Observed::new(chain_tip.min(end), Vec::new()));
        }

        let mut found = Vec::new();
        let mut forced = Vec::new();
        // The trees first, and **contiguously**: from where they stopped to
        // the ceiling the lag allows, whatever range the deposit scan wants.
        // A tree is only a tree if every commitment is in it, in order; a
        // block appended after a gap is a different tree with a root the
        // chain never had. The deposit range below may overlap or not — the
        // watcher deduplicates by txid, so a deposit seen twice is credited
        // once.
        let mut fed: Option<(u64, u64)> = None;
        if let Some(store) = &self.notes {
            let tree_ceiling = chain_tip.saturating_sub(self.tree_lag);
            let tree_from = store
                .synced_to()
                .map(|h| h + 1)
                .unwrap_or(self.from_height)
                .max(self.from_height);
            let tree_to =
                tree_ceiling.min(tree_from.saturating_add(self.max_blocks).saturating_sub(1));
            if tree_from <= tree_to {
                for height in tree_from..=tree_to {
                    let (d, f) = self.feed_block(zebra, store, height)?;
                    found.extend(d);
                    forced.extend(f);
                }
                fed = Some((tree_from, tree_to));
            }
        }
        for height in start..=end {
            if fed
                .map(|(a, b)| height >= a && height <= b)
                .unwrap_or(false)
            {
                continue; // read once already, above
            }
            for txid_hex in zebra.block_txids(height)? {
                let raw = zebra.raw_transaction_bytes(&txid_hex)?;
                let Some(txid) = txid_bytes(&txid_hex) else {
                    continue;
                };
                // A transaction we cannot parse is not our problem: the
                // chain contains every version there has ever been.
                let Ok(scanned) = self.keys.scan_actions_lenient(&raw, txid, height) else {
                    continue;
                };
                // The tree has this block already (the settler fed it to
                // build an anchor), so its spends are applied — but the store
                // remembers which nullifiers were ours, and that is what
                // tells our own change from a stranger's memo-less deposit.
                let spends_ours = match &self.notes {
                    Some(stores) => scanned.actions.iter().any(|a| {
                        stores
                            .of(a.pool)
                            .lock()
                            .map(|s| s.holds_nullifier(&a.nullifier, self.keys.fvk()))
                            .unwrap_or(false)
                    }),
                    None => false,
                };
                let handed_out = self.addresses.lock().map(|m| m.clone()).unwrap_or_default();
                found.extend(
                    classify_addressed(
                        &scanned,
                        spends_ours,
                        self.attributions.get(&txid).copied(),
                        txid,
                        height,
                        &handed_out,
                    )
                    .map_err(|amount| ScanRangeError::Unattributable { height, amount })?,
                );
                forced.extend(scanned.forced);
            }
        }
        let mut observed = crate::zebra::Observed::new(end, found);
        observed.set_forced(forced);
        Ok(observed)
    }

    /// Forced intents between `from` and `to` inclusive, in chain order. What
    /// a replica runs: it holds the sequencer to every one of them.
    pub fn forced(
        &self,
        zebra: &crate::zebra::Zebra,
        from: u64,
        to: u64,
    ) -> Result<(u64, Vec<ForcedSighting>), ScanRangeError> {
        let start = from.max(self.from_height);
        let end = to.min(start.saturating_add(self.max_blocks).saturating_sub(1));
        let mut found = Vec::new();
        if end < start {
            return Ok((to.min(end), found));
        }
        for height in start..=end {
            for txid_hex in zebra.block_txids(height)? {
                let raw = zebra.raw_transaction_bytes(&txid_hex)?;
                let Some(txid) = txid_bytes(&txid_hex) else {
                    continue;
                };
                let Ok(scanned) = self.keys.scan_actions_lenient(&raw, txid, height) else {
                    continue;
                };
                found.extend(scanned.forced);
            }
        }
        Ok((end, found))
    }

    /// Purpose-bound application payments between `from` and `to`, in canonical
    /// block/transaction/output order. The ordinary bridge excludes these
    /// notes from account credits; the application consumes this view.
    pub fn app_payments(
        &self,
        zebra: &crate::zebra::Zebra,
        from: u64,
        to: u64,
    ) -> Result<(u64, Vec<AppPaymentSighting>), ScanRangeError> {
        let start = from.max(self.from_height);
        let end = to.min(start.saturating_add(self.max_blocks).saturating_sub(1));
        let mut found = Vec::new();
        if end < start {
            return Ok((to.min(end), found));
        }
        for height in start..=end {
            for (tx_index, txid_hex) in zebra.block_txids(height)?.into_iter().enumerate() {
                let raw = zebra.raw_transaction_bytes(&txid_hex)?;
                let Some(txid) = txid_bytes(&txid_hex) else {
                    continue;
                };
                let Ok(scanned) = self.keys.scan_actions_lenient(&raw, txid, height) else {
                    continue;
                };
                let tx_index = u32::try_from(tx_index).map_err(|_| {
                    ScanRangeError::Rpc(crate::zebra::RpcError::Malformed(
                        "too many transactions in one block",
                    ))
                })?;
                found.extend(
                    scanned
                        .app_payments
                        .into_iter()
                        .map(|output| AppPaymentSighting {
                            txid: output.txid,
                            height: output.height,
                            tx_index,
                            output_index: output.output_index,
                            amount: output.amount,
                            payment: output.payment,
                        }),
                );
            }
        }
        Ok((end, found))
    }

    /// The vault's anchor self-sends between `from` and `to` inclusive, in
    /// chain order. Bounded by `max_blocks` like [`Self::observe`]; the
    /// caller advances from the last height returned.
    ///
    /// What a replica runs: it needs the viewing key and a node, and nothing
    /// from the sequencer.
    pub fn anchors(
        &self,
        zebra: &crate::zebra::Zebra,
        from: u64,
        to: u64,
    ) -> Result<(u64, Vec<AnchorSighting>), ScanRangeError> {
        let start = from.max(self.from_height);
        let end = to.min(start.saturating_add(self.max_blocks).saturating_sub(1));
        let mut found = Vec::new();
        if end < start {
            return Ok((to.min(end), found));
        }
        for height in start..=end {
            for txid_hex in zebra.block_txids(height)? {
                let raw = zebra.raw_transaction_bytes(&txid_hex)?;
                let Some(txid) = txid_bytes(&txid_hex) else {
                    continue;
                };
                let Ok(scanned) = self.keys.scan_actions_lenient(&raw, txid, height) else {
                    continue;
                };
                for a in scanned.actions.iter().filter(|a| a.anchor) {
                    let Some(m) = &a.memo else { continue };
                    let mut memo = [0u8; memo::ANCHOR_LEN];
                    memo.copy_from_slice(&m[..memo::ANCHOR_LEN]);
                    found.push(AnchorSighting { height, txid, memo });
                }
            }
        }
        Ok((end, found))
    }

    /// Replace a diverged tree with one seeded from the node's frontier at the
    /// vault's birth, then walk every block again. Returns what the old tree
    /// had appended and what the node has at the same height — the number
    /// that says whether a block was fed twice, skipped, or reorganised.
    pub fn reseed(
        &self,
        zebra: &crate::zebra::Zebra,
        pool: ValuePool,
        to: u64,
    ) -> Result<(u64, u64, u64), ScanRangeError> {
        let Some(stores) = &self.notes else {
            return Ok((0, 0, 0));
        };
        let seed_height = self.from_height.saturating_sub(1);
        let store = stores.of(pool);
        let (old_appended, old_at) = {
            let s = store.lock().map_err(|_| {
                ScanRangeError::Rpc(crate::zebra::RpcError::Malformed("note store poisoned"))
            })?;
            (s.appended(), s.synced_to().unwrap_or(seed_height))
        };
        // What the node has at the height the old tree claimed.
        let at_node = zebra.tree_state_of(old_at, pool)?;
        let node_count = NoteStore::from_frontier(&at_node.final_state, old_at)
            .map(|s| s.appended())
            .unwrap_or(0);
        let ts = zebra.tree_state_of(seed_height, pool)?;
        let fresh = NoteStore::from_frontier(&ts.final_state, seed_height).map_err(|_| {
            ScanRangeError::Rpc(crate::zebra::RpcError::Malformed(
                "cannot seed from the node's frontier",
            ))
        })?;
        {
            let mut s = store.lock().map_err(|_| {
                ScanRangeError::Rpc(crate::zebra::RpcError::Malformed("note store poisoned"))
            })?;
            *s = fresh;
        }
        // Both trees walk together in `feed_block`; bring the other pool to the
        // same start so a block is never half-fed.
        let other = match pool {
            ValuePool::Orchard => ValuePool::Ironwood,
            ValuePool::Ironwood => ValuePool::Orchard,
        };
        let ts2 = zebra.tree_state_of(seed_height, other)?;
        if let Ok(fresh2) = NoteStore::from_frontier(&ts2.final_state, seed_height) {
            if let Ok(mut s) = stores.of(other).lock() {
                *s = fresh2;
            }
        }
        let mut synced = seed_height;
        while synced < to {
            synced = self.sync_notes(zebra, to)?;
        }
        Ok((old_appended, node_count, old_at))
    }

    /// Feed the tree, and only the tree, from where it is up to `to`.
    ///
    /// For a restart: the deposit watcher resumes above its own progress, but
    /// the tree needs every commitment from the vault's frontier onward, so
    /// this walks the gap without crediting anything. Bounded like `observe`;
    /// call until it reports `to`.
    pub fn sync_notes(&self, zebra: &crate::zebra::Zebra, to: u64) -> Result<u64, ScanRangeError> {
        let Some(store) = &self.notes else {
            return Ok(to);
        };
        let start = store
            .synced_to()
            .map(|h| h + 1)
            .unwrap_or(self.from_height)
            .max(self.from_height);
        let end = to.min(start.saturating_add(self.max_blocks).saturating_sub(1));
        if end < start {
            return Ok(to.min(start.saturating_sub(1)));
        }
        for height in start..=end {
            self.feed_block(zebra, store, height)?;
        }
        Ok(end)
    }

    /// Append every commitment in one block, all or nothing.
    fn feed_block(
        &self,
        zebra: &crate::zebra::Zebra,
        stores: &PoolStores,
        height: u64,
    ) -> Result<(Vec<ObservedDeposit>, Vec<ForcedSighting>), ScanRangeError> {
        let poisoned =
            || ScanRangeError::Rpc(crate::zebra::RpcError::Malformed("note store poisoned"));
        let mut o = stores.orchard.lock().map_err(|_| poisoned())?;
        let mut i = stores.ironwood.lock().map_err(|_| poisoned())?;
        // From the guards already held — `stores.synced_to()` would lock
        // them a second time, and a std mutex is not re-entrant.
        let done = match (o.synced_to(), i.synced_to()) {
            (Some(a), Some(b)) => height <= a.min(b),
            _ => false,
        };
        if done {
            return Ok((Vec::new(), Vec::new())); // already in
        }
        o.begin_block(height);
        i.begin_block(height);
        // Everything below either completes the block or rewinds it. A block
        // half-appended would shift every later position by the missing tail
        // and every witness with it.
        let result = (|| {
            let mut deposits = Vec::new();
            let mut forced = Vec::new();
            for txid_hex in zebra.block_txids(height)? {
                let raw = zebra.raw_transaction_bytes(&txid_hex)?;
                let Some(txid) = txid_bytes(&txid_hex) else {
                    continue;
                };
                // Lenient here, and strict below, once we know what the
                // transaction is: one that spends our own note is one we
                // sent, and a note it returns to us is **change** — held,
                // never credited, never a reason to stop.
                let scanned = match self.keys.scan_actions_lenient(&raw, txid, height) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let spends_ours = scanned.actions.iter().any(|a| match a.pool {
                    ValuePool::Orchard => o.holds_nullifier(&a.nullifier, self.keys.fvk()),
                    ValuePool::Ironwood => i.holds_nullifier(&a.nullifier, self.keys.fvk()),
                });
                // A note whose nullifier is on the chain is gone, whoever
                // spent it (only we can). Forgetting it here, from the chain,
                // is what keeps a rebuilt tree from offering a spent note to
                // the next payout.
                for a in &scanned.actions {
                    let s = match a.pool {
                        ValuePool::Orchard => &mut o,
                        ValuePool::Ironwood => &mut i,
                    };
                    s.spend_nullifier(&a.nullifier, self.keys.fvk());
                }
                deposits.extend(
                    classify(
                        &scanned,
                        spends_ours,
                        self.attributions.get(&txid).copied(),
                        txid,
                        height,
                    )
                    .map_err(|amount| ScanRangeError::Unattributable { height, amount })?,
                );
                forced.extend(scanned.forced.iter().cloned());
                for a in scanned.actions {
                    let s = match a.pool {
                        ValuePool::Orchard => &mut o,
                        ValuePool::Ironwood => &mut i,
                    };
                    let pos = s.append(&a.cmx, a.ours.is_some());
                    if let (Some(note), Some(pos)) = (a.ours, pos) {
                        s.hold(note, pos, height, txid);
                    }
                }
            }
            Ok((deposits, forced))
        })();
        match result {
            Ok(d) => {
                o.finish_block(height);
                i.finish_block(height);
                Ok(d)
            }
            Err(e) => {
                o.rewind();
                i.rewind();
                Err(e)
            }
        }
    }
}

/// A txid is displayed big-endian and stored little-endian, so the hex a node
/// prints is the reverse of the bytes a transaction commits to.
fn txid_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    out.reverse();
    Some(out)
}

/// Deposits found across a range of blocks, ready to hand the watcher.
pub fn collect(deposits: Vec<ObservedDeposit>) -> BTreeMap<u64, Vec<ObservedDeposit>> {
    let mut by_height: BTreeMap<u64, Vec<ObservedDeposit>> = BTreeMap::new();
    for d in deposits {
        by_height.entry(d.height).or_default().push(d);
    }
    by_height
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> VaultKeys {
        VaultKeys::from_spending_key([7u8; 32]).expect("a valid spending key")
    }

    #[test]
    fn a_vault_has_an_orchard_only_unified_address() {
        let a = keys().address(0, NetworkType::Test);
        // Testnet unified addresses are `utest1...`.
        assert!(
            a.starts_with("utest1"),
            "not a testnet unified address: {}",
            a
        );
        // Different diversifier indices give different addresses, which is
        // what per-account deposit addressing would use.
        assert_ne!(
            keys().address(0, NetworkType::Test),
            keys().address(1, NetworkType::Test)
        );
    }

    #[test]
    fn the_same_key_always_derives_the_same_address() {
        assert_eq!(
            keys().address(0, NetworkType::Test),
            keys().address(0, NetworkType::Test)
        );
        let other = VaultKeys::from_spending_key([8u8; 32]).unwrap();
        assert_ne!(
            keys().address(0, NetworkType::Test),
            other.address(0, NetworkType::Test)
        );
    }

    /// **S10**, at the widest input surface we have: every transaction on a
    /// public chain is fed to this, including whatever an attacker mines.
    #[test]
    fn junk_bytes_are_refused_rather_than_fatal() {
        let k = keys();
        assert_eq!(
            k.scan_transaction(&[], [0u8; 32], 1),
            Err(ScanError::Undecodable)
        );
        assert_eq!(
            k.scan_transaction(&[0xFF; 9], [0u8; 32], 1),
            Err(ScanError::Undecodable)
        );
        for n in 0..64 {
            let junk = vec![0xABu8; n];
            let _ = k.scan_transaction(&junk, [0u8; 32], 1);
        }
    }

    #[test]
    fn deposits_group_by_height() {
        let d = |h: u64, n: u8| ObservedDeposit {
            txid: [n; 32],
            account: [n; 32],
            amount: Fixed::whole(1),
            height: h,
            asset: None,
        };
        let m = collect(vec![d(5, 1), d(5, 2), d(7, 3)]);
        assert_eq!(m[&5].len(), 2);
        assert_eq!(m[&7].len(), 1);
    }
}

/// Proving that trial decryption actually works, without a proving key.
///
/// A real deposit arrives inside a proved Orchard bundle, which a test cannot
/// build cheaply. What it *can* build is the ciphertext and the domain that
/// decrypts it — which is the part this module is responsible for. The bundle
/// around it is Zcash's problem and Zcash tests it.
#[cfg(test)]
mod roundtrip {
    use super::*;
    use orchard::note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho};
    use orchard::note_encryption::{CompactAction, OrchardDomain};
    use orchard::value::NoteValue;
    use zcash_note_encryption::{
        Domain, EphemeralKeyBytes, NoteEncryption, ShieldedOutput, COMPACT_NOTE_SIZE,
        ENC_CIPHERTEXT_SIZE,
    };
    use crate::account::AccountId;

    /// The full-size output a real `Action` provides. A `CompactAction` carries
    /// only 52 bytes — enough for the note, never enough for the memo, and the
    /// memo is where the account lives.
    struct FullOutput {
        epk: EphemeralKeyBytes,
        cmx: [u8; 32],
        enc: [u8; ENC_CIPHERTEXT_SIZE],
    }

    impl ShieldedOutput<OrchardDomain, ENC_CIPHERTEXT_SIZE> for FullOutput {
        fn ephemeral_key(&self) -> EphemeralKeyBytes {
            self.epk.clone()
        }
        fn cmstar_bytes(&self) -> [u8; 32] {
            self.cmx
        }
        fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
            &self.enc
        }
    }

    fn deposit_to(keys: &VaultKeys, account: AccountId, zat: u64) -> (FullOutput, OrchardDomain) {
        let mut memo = [0u8; 512];
        let encoded = memo::encode(&account);
        memo[..encoded.len()].copy_from_slice(&encoded);
        output_with_memo(keys, memo, zat)
    }

    fn output_with_memo(
        keys: &VaultKeys,
        memo: [u8; 512],
        zat: u64,
    ) -> (FullOutput, OrchardDomain) {
        let recipient = keys.fvk.address_at(0u32, Scope::External);
        let nf = Nullifier::from_bytes(&[9u8; 32]).unwrap();
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let rseed = RandomSeed::from_bytes([4u8; 32], &rho).unwrap();
        let note = orchard::Note::from_parts(
            recipient,
            NoteValue::from_raw(zat),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        )
        .unwrap();

        let ne = NoteEncryption::<OrchardDomain>::new(None, note, memo);
        let enc = ne.encrypt_note_plaintext();
        let epk = <OrchardDomain as Domain>::epk_bytes(ne.epk());
        let cmx_note = ExtractedNoteCommitment::from(note.commitment());
        let cmx = cmx_note.to_bytes();

        let mut compact = [0u8; COMPACT_NOTE_SIZE];
        compact.copy_from_slice(&enc[..COMPACT_NOTE_SIZE]);
        let ca = CompactAction::from_parts(nf, cmx_note, epk.clone(), compact);
        (
            FullOutput { epk, cmx, enc },
            OrchardDomain::for_compact_action(&ca),
        )
    }

    /// The whole point: a shielded payment to the vault is found, its value
    /// read, and the account recovered from the memo.
    #[test]
    fn a_shielded_deposit_is_found_and_attributed() {
        let keys = VaultKeys::from_spending_key([7u8; 32]).unwrap();
        let account: AccountId = [0x5A; 32];
        let (out, domain) = deposit_to(&keys, account, 100_000);

        let (note, _addr, memo) =
            zcash_note_encryption::try_note_decryption(&domain, &keys.ivk, &out)
                .expect("the vault must be able to decrypt its own deposit");

        assert_eq!(note.value().inner(), 100_000);
        assert_eq!(
            Fixed(note.value().inner() as i128 * ZAT),
            Fixed::raw(100_000 * ZAT)
        );
        assert_eq!(
            memo::decode(&memo),
            Ok(account),
            "the memo did not name the depositor"
        );
    }

    /// An anchor is the vault paying itself with a state root in the memo. The
    /// scanner must see it as evidence, not as a deposit and not as a problem.
    #[test]
    fn an_anchor_self_send_is_recognised_and_never_credited() {
        let keys = VaultKeys::from_spending_key([7u8; 32]).unwrap();
        let mut anchor_memo = [0u8; 512];
        anchor_memo[..3].copy_from_slice(memo::ANCHOR_TAG);
        anchor_memo[3] = memo::MEMO_VERSION;
        anchor_memo[4..memo::ANCHOR_LEN].copy_from_slice(&[0xA1; memo::ANCHOR_LEN - 4]);
        let (out, domain) = output_with_memo(&keys, anchor_memo, 10_000);
        let (note, _addr, memo_back) =
            zcash_note_encryption::try_note_decryption(&domain, &keys.ivk, &out).expect("own note");
        assert!(memo::is_anchor(&memo_back));
        // Drive the same decision `take` makes, then `classify` on top of it.
        let mut scanned = Scanned::default();
        let nf = Nullifier::from_bytes(&[9u8; 32]).unwrap();
        scanned.actions.push(ScannedAction {
            pool: ValuePool::Orchard,
            cmx: ExtractedNoteCommitment::from(note.commitment()),
            nullifier: nf,
            ours: Some(note),
            account: None,
            memo: Some(memo_back.to_vec()),
            to_index: None,
            anchor: memo::is_anchor(&memo_back),
            forced: None,
            app_payment: None,
            app_reserved: false,
        });
        // Even in a transaction that does not visibly spend our note and with
        // no attribution, an anchor is not an unaddressed deposit.
        assert_eq!(classify(&scanned, false, None, [1u8; 32], 5), Ok(vec![]));
    }

    #[test]
    fn an_app_payment_is_surfaced_once_and_never_credited_as_a_deposit() {
        let keys = VaultKeys::from_spending_key([7u8; 32]).unwrap();
        let payment = memo::AppPaymentMemo {
            purpose: memo::Purpose(1),
            reference: [0x44; 32],
            recipient: [0x55; 32],
        };
        let encoded = memo::encode_app_payment(payment).unwrap();
        let (out, domain) = output_with_memo(&keys, encoded, 1_000_000);
        let decrypted = zcash_note_encryption::try_note_decryption(&domain, &keys.ivk, &out)
            .expect("own application payment");
        let note = decrypted.0;
        let index = keys.index_of(&note).unwrap();
        let nf = Nullifier::from_bytes(&[9u8; 32]).unwrap();
        let mut scanned = Scanned::default();
        keys.take(
            &mut scanned,
            ValuePool::Orchard,
            ExtractedNoteCommitment::from(note.commitment()),
            nf,
            Some(decrypted),
            [0x66; 32],
            90,
            3,
            &BTreeMap::new(),
            false,
        )
        .unwrap();

        assert!(scanned.deposits.is_empty());
        assert_eq!(scanned.app_payments.len(), 1);
        assert_eq!(scanned.app_payments[0].payment, payment);
        assert_eq!(scanned.app_payments[0].output_index, 3);
        let mut handed_out = BTreeMap::new();
        handed_out.insert(index, payment.recipient);
        assert_eq!(
            classify_addressed(&scanned, false, None, [0x66; 32], 90, &handed_out),
            Ok(vec![]),
            "an issued address must not turn an application payment into a deposit"
        );

        let mut malformed = encoded;
        malformed[3] = memo::APP_PAYMENT_VERSION + 1;
        let (bad_out, bad_domain) = output_with_memo(&keys, malformed, 1_000_000);
        let bad_decrypted =
            zcash_note_encryption::try_note_decryption(&bad_domain, &keys.ivk, &bad_out)
                .expect("own malformed application payment");
        let mut lenient = Scanned::default();
        keys.take(
            &mut lenient,
            ValuePool::Orchard,
            ExtractedNoteCommitment::from(bad_decrypted.0.commitment()),
            Nullifier::from_bytes(&[9u8; 32]).unwrap(),
            Some(bad_decrypted),
            [0x77; 32],
            91,
            0,
            &BTreeMap::new(),
            true,
        )
        .unwrap();
        assert!(lenient.app_payments.is_empty());
        assert_eq!(
            classify_addressed(&lenient, false, None, [0x77; 32], 91, &handed_out),
            Err(Fixed::raw(1_000_000 * ZAT)),
            "a malformed ZYC memo must fail closed before address attribution"
        );
    }

    /// Someone else's vault key must not see it. This is the property that
    /// makes a shielded deposit private in the first place.
    #[test]
    fn another_vault_sees_nothing() {
        let ours = VaultKeys::from_spending_key([7u8; 32]).unwrap();
        let theirs = VaultKeys::from_spending_key([8u8; 32]).unwrap();
        let (out, domain) = deposit_to(&ours, [1u8; 32], 5_000);

        assert!(
            zcash_note_encryption::try_note_decryption(&domain, &theirs.ivk, &out).is_none(),
            "a different viewing key decrypted our deposit"
        );
    }

    /// Shielded funds with no recognised memo are visible and unattributable. That is
    /// a real event — someone sent the vault money without saying who for —
    /// and it must be reported rather than silently dropped.
    #[test]
    fn a_deposit_without_a_memo_is_reported_not_swallowed() {
        let keys = VaultKeys::from_spending_key([7u8; 32]).unwrap();
        let recipient = keys.fvk.address_at(0u32, Scope::External);
        let nf = Nullifier::from_bytes(&[9u8; 32]).unwrap();
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let rseed = RandomSeed::from_bytes([4u8; 32], &rho).unwrap();
        let note = orchard::Note::from_parts(
            recipient,
            NoteValue::from_raw(1),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        )
        .unwrap();
        let ne = NoteEncryption::<OrchardDomain>::new(None, note, [0u8; 512]);
        let enc = ne.encrypt_note_plaintext();
        let epk = <OrchardDomain as Domain>::epk_bytes(ne.epk());
        let cmx_note = ExtractedNoteCommitment::from(note.commitment());
        let cmx = cmx_note.to_bytes();
        let mut compact = [0u8; COMPACT_NOTE_SIZE];
        compact.copy_from_slice(&enc[..COMPACT_NOTE_SIZE]);
        let ca = CompactAction::from_parts(nf, cmx_note, epk.clone(), compact);
        let domain = OrchardDomain::for_compact_action(&ca);
        let out = FullOutput { epk, cmx, enc };

        let (_n, _a, memo) =
            zcash_note_encryption::try_note_decryption(&domain, &keys.ivk, &out).unwrap();
        assert!(
            memo::decode(&memo).is_err(),
            "an empty memo must not decode to an account"
        );
    }
}

#[cfg(test)]
mod deposit_address_tests {
    use super::*;
    use orchard::keys::SpendingKey;

    fn keys() -> VaultKeys {
        VaultKeys::from_full_viewing_key(FullViewingKey::from(
            &SpendingKey::from_bytes([7u8; 32]).unwrap(),
        ))
    }

    /// The index is a function of the account and nothing else, so a verifier
    /// recomputes it from the credit alone.
    #[test]
    fn a_deposit_index_is_derived_from_the_account_and_is_never_the_vaults_own() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(deposit_index(&a), deposit_index(&a), "deterministic");
        assert_ne!(
            deposit_index(&a),
            deposit_index(&b),
            "distinct accounts, distinct addresses"
        );
        for acct in [[0u8; 32], a, b, [0xffu8; 32]] {
            assert_ne!(
                *deposit_index(&acct).as_bytes(),
                VAULT_INDEX,
                "never the vault's own index"
            );
        }
    }

    /// The round trip that makes ownership checkable: derive an account's
    /// address, and recover the account's index from a note sent to it.
    #[test]
    fn a_note_sent_to_an_accounts_address_reports_that_accounts_index() {
        let k = keys();
        let account = [9u8; 32];
        let addr = k.fvk.address_at(deposit_index(&account), Scope::External);
        let recovered = k.plain_ivk.diversifier_index(&addr).expect("ours");
        assert_eq!(recovered, deposit_index(&account));

        // The vault's own address is index zero, and is not any account's.
        let own = k.fvk.address_at(0u32, Scope::External);
        let own_index = k.plain_ivk.diversifier_index(&own).expect("ours");
        assert_eq!(*own_index.as_bytes(), VAULT_INDEX);
        assert_ne!(own_index, deposit_index(&account));
    }

    /// The bug this exists to prevent.
    ///
    /// The encoding was hardcoded to testnet, so a mainnet vault would have
    /// handed out `utest1…` addresses. A mainnet wallet rejects those on the
    /// HRP, so nobody would have lost funds — the mint simply could not have
    /// happened, and we would have found out from the first buyer.
    #[test]
    fn an_address_is_encoded_for_the_network_it_is_meant_for() {
        let k = keys();
        let account = [5u8; 32];
        let test = k.deposit_address(&account, NetworkType::Test);
        let main = k.deposit_address(&account, NetworkType::Main);

        assert!(test.starts_with("utest1"), "{}", test);
        assert!(main.starts_with("u1"), "{}", main);
        assert_ne!(test, main, "the same key on two chains is two addresses");

        // The vault's own address follows the same rule.
        assert!(k.address(0, NetworkType::Test).starts_with("utest1"));
        assert!(k.address(0, NetworkType::Main).starts_with("u1"));
    }

    /// Different accounts get different addresses, and the encoding is a
    /// Zcash unified address a wallet will accept.
    #[test]
    fn each_account_gets_its_own_unified_address() {
        let k = keys();
        let a = k.deposit_address(&[1u8; 32], NetworkType::Test);
        let b = k.deposit_address(&[2u8; 32], NetworkType::Test);
        assert_ne!(a, b);
        assert!(a.starts_with('u'), "{}", a);
        assert_ne!(
            a,
            k.address(0, NetworkType::Test),
            "an account's address is not the vault's own"
        );
    }
}
