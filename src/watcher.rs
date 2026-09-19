//! Turning confirmed on-chain deposits into intents.
//!
//! The VM cannot see Zcash, so something has to look and report. This is that
//! something, and it is where the interesting mistakes live — not in the
//! looking, which is a node call, but in deciding *when* a deposit is real,
//! *whether it has already been reported*, and *in what order* to say so.
//!
//! Chain access sits behind [`ChainView`] because none of that logic needs a
//! Zcash node to be written or tested, and all of it needs to be right. A reorg
//! is a two-line change to a mock and a very expensive incident in production.
//!
//! # What the VM demands, and why it shapes this
//!
//! - A credit may not exceed the vault's last **observed** balance, so an
//!   observation must be reported before the deposits it covers.
//! - Deposit indices are strictly sequential, so a gap or a repeat is refused.
//! - A credit is not spendable until its epoch is anchored, so being slightly
//!   slow here costs nothing and being wrong costs everything.
//!
//! The watcher therefore prefers to say nothing over saying something twice.

use alloc_shim::*;
mod alloc_shim {
    pub use std::collections::BTreeSet;
    pub use std::vec::Vec;
}

use crate::account::AccountId;
use crate::amount::Fixed;

pub type AssetId = [u8; 32];

/// A deposit seen on the custodying chain.
///
/// Producing one requires the vault's viewing key: a shielded deposit is not
/// public, and only a key holder can see the amount or the memo that names the
/// recipient. That is the trust this whole path rests on, and the reason the
/// key belongs with the signers rather than with one operator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObservedDeposit {
    /// Transaction identifier on the custodying chain.
    pub txid: [u8; 32],
    /// The Zyn account it credits, from the deposit's memo or its derived
    /// address.
    pub account: AccountId,
    pub amount: Fixed,
    /// Block height it was mined at.
    pub height: u64,
    /// The Zyn asset this credits, when the chain view knows more than one —
    /// a vault that holds SOL and mirrored NFTs. `None` means the bridge's
    /// own asset.
    pub asset: Option<AssetId>,
}

/// What the watcher needs from a chain.
///
/// Deliberately small, and deliberately *by height*: a watcher that could only
/// ask "what is true now" could not tell a reorg from a quiet period.
pub trait ChainView {
    /// Height of the current tip.
    fn tip(&self) -> u64;

    /// Deposits to the vault mined at exactly `height`, decrypted with the
    /// viewing key. Empty for a height with none, and for a height that no
    /// longer exists.
    fn deposits_at(&self, height: u64) -> Vec<ObservedDeposit>;

    /// What the vault holds as of `height`, in the asset's own units.
    fn balance_at(&self, height: u64) -> Option<Fixed>;

    /// Whether any answer this view gave since it was refreshed was a guess
    /// forced by a failure.
    ///
    /// The methods above are infallible by design, so a view that could not
    /// reach its node has to answer *something* — and "no deposits here" is
    /// the wrong something to record as progress: the watcher would mark the
    /// height scanned and a real deposit in it would never be seen again.
    /// A caller checks this after a pass and, if set, records nothing.
    fn failed(&self) -> bool {
        false
    }

    /// What the vault holds of `asset` — an asset other than the bridge's
    /// own, for a view over several (see [`ObservedDeposit::asset`]).
    fn balance_of(&self, _asset: AssetId, _height: u64) -> Option<Fixed> {
        None
    }
}

/// A borrowed view is still a view.
///
/// Lets a caller hold a long-lived chain client (an EVM one keeps a connection
/// and a cached tip) and hand out `&dyn ChainView` beside arms that yield an
/// owned snapshot, without copying either.
impl<T: ChainView + ?Sized> ChainView for &T {
    fn tip(&self) -> u64 {
        (**self).tip()
    }
    fn deposits_at(&self, height: u64) -> Vec<ObservedDeposit> {
        (**self).deposits_at(height)
    }
    fn balance_at(&self, height: u64) -> Option<Fixed> {
        (**self).balance_at(height)
    }
    fn failed(&self) -> bool {
        (**self).failed()
    }
    fn balance_of(&self, asset: AssetId, height: u64) -> Option<Fixed> {
        (**self).balance_of(asset, height)
    }
}

/// An intent the watcher wants sequenced.
///
/// Named rather than constructed as an application's `Intent`, because the
/// watcher belongs to no application: a VM holding bridged value maps these
/// onto its own alphabet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WatcherAction {
    /// Report the vault's balance. Always emitted before the credits it covers.
    Attest { observed: Fixed },
    /// Credit one deposit.
    Credit {
        account: AccountId,
        amount: Fixed,
        index: u64,
        external_ref: [u8; 32],
        /// See [`ObservedDeposit::asset`].
        asset: Option<AssetId>,
    },
    /// Report what the vault holds of one *other* asset it custodies — a
    /// mirrored NFT's mint — before crediting it. Always before the credits
    /// it covers.
    AttestAsset { asset: AssetId, observed: Fixed },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WatcherError {
    /// The chain could not answer for a height the watcher needs. Not fatal:
    /// the watcher makes no progress and tries again.
    Unavailable,
    /// A deposit already credited is no longer on the chain. Units have been
    /// issued against something that did not happen, and no amount of watching
    /// fixes it — this is an alarm, not a retry.
    CreditedDepositReorgedOut { txid: [u8; 32] },
}

/// Follows a chain and reports what is safely confirmed.
#[derive(Clone, Debug)]
pub struct Watcher {
    /// Blocks a deposit must be buried under before it is reported.
    ///
    /// The whole reorg defence. A deposit is not reported until reversing it
    /// would take more work than an attacker is assumed to have — which is a
    /// policy judgement about the chain, not something the VM can decide.
    confirmations: u64,
    /// Highest height whose deposits have been reported.
    scanned_to: u64,
    /// Transactions already credited, so a reorg that reshuffles blocks cannot
    /// produce a second credit for one.
    ///
    /// Grows with deposits. A production watcher prunes below the finalised
    /// height, where a reorg is no longer possible; keeping it whole here is
    /// the simpler thing and the tests care about the logic, not the memory.
    credited: BTreeSet<[u8; 32]>,
    /// The next deposit index the VM will accept.
    next_index: u64,
}

impl Watcher {
    pub fn new(confirmations: u64, next_index: u64) -> Watcher {
        Watcher {
            confirmations,
            scanned_to: 0,
            credited: BTreeSet::new(),
            next_index,
        }
    }

    /// Resume a watcher that has run before.
    pub fn resume(confirmations: u64, next_index: u64, scanned_to: u64) -> Watcher {
        Watcher {
            confirmations,
            scanned_to,
            credited: BTreeSet::new(),
            next_index,
        }
    }

    pub fn scanned_to(&self) -> u64 {
        self.scanned_to
    }
    pub fn confirmations(&self) -> u64 {
        self.confirmations
    }

    /// Forget progress past `height`, keeping everything already credited.
    /// For a pass whose chain view turned out to be lying (see
    /// [`ChainView::failed`]).
    pub fn rewind_to(&mut self, height: u64) {
        if height < self.scanned_to {
            self.scanned_to = height;
        }
    }
    pub fn next_index(&self) -> u64 {
        self.next_index
    }
    pub fn credited_count(&self) -> usize {
        self.credited.len()
    }

    /// The highest height that is safely confirmed at the current tip.
    fn safe_height(&self, tip: u64) -> Option<u64> {
        tip.checked_sub(self.confirmations.saturating_sub(1))?
            .checked_sub(1)
            .map(|h| h + 1)
    }

    /// Scan forward and produce the intents for everything newly confirmed.
    ///
    /// Returns an empty list when there is nothing new, which is the common
    /// case and must be cheap. Makes no progress at all if the chain cannot
    /// answer — a partial scan that advanced `scanned_to` would skip the
    /// heights it failed on, and those deposits would never be seen again.
    pub fn poll<C: ChainView + ?Sized>(
        &mut self,
        chain: &C,
    ) -> Result<Vec<WatcherAction>, WatcherError> {
        let tip = chain.tip();
        let Some(safe) = self.safe_height(tip) else {
            return Ok(Vec::new()); // chain too short to confirm anything yet
        };
        if safe <= self.scanned_to {
            return Ok(Vec::new());
        }

        // Collect first, emit second. A deposit that turns out to be a repeat
        // must not leave a half-built batch behind.
        let mut fresh: Vec<ObservedDeposit> = Vec::new();
        for height in (self.scanned_to + 1)..=safe {
            for d in chain.deposits_at(height) {
                if self.credited.contains(&d.txid) {
                    continue; // already reported; a reshuffled block is not a new deposit
                }
                if !d.amount.is_positive() {
                    continue;
                }
                // The all-zero account is nobody: a top-up of the vault that
                // raises the attested balance and credits no one.
                if d.account == [0u8; 32] {
                    continue;
                }
                fresh.push(d);
            }
        }
        // Deterministic order: two watchers scanning the same range must
        // produce the same indices, or they disagree about the chain.
        fresh.sort_by_key(|d| (d.height, d.txid));

        if fresh.is_empty() {
            self.scanned_to = safe;
            return Ok(Vec::new());
        }

        // The observation must cover the credits that follow it, and must come
        // from the same height they were confirmed at — a balance read at the
        // tip could include deposits this batch does not credit.
        let observed = chain.balance_at(safe).ok_or(WatcherError::Unavailable)?;
        let mut actions = Vec::with_capacity(fresh.len() + 1);
        actions.push(WatcherAction::Attest { observed });
        // Each other asset being credited gets its own attestation first.
        let mut others: Vec<AssetId> = fresh.iter().filter_map(|d| d.asset).collect();
        others.sort_unstable();
        others.dedup();
        for a in others {
            let observed = chain.balance_of(a, safe).ok_or(WatcherError::Unavailable)?;
            actions.push(WatcherAction::AttestAsset { asset: a, observed });
        }
        for d in &fresh {
            actions.push(WatcherAction::Credit {
                account: d.account,
                amount: d.amount,
                index: self.next_index,
                external_ref: d.txid,
                asset: d.asset,
            });
            self.next_index += 1;
            self.credited.insert(d.txid);
        }
        self.scanned_to = safe;
        Ok(actions)
    }

    /// Check that every deposit already credited is still on the chain.
    ///
    /// Confirmation depth makes this improbable, not impossible. If it ever
    /// fires, units exist that nothing backs, and nothing the watcher can do
    /// repairs that — the vault is short and the response is governance, not
    /// retry. Naming it is the only useful thing code can do.
    pub fn audit<C: ChainView>(
        &self,
        chain: &C,
        from_height: u64,
        to_height: u64,
    ) -> Result<(), WatcherError> {
        let mut seen = BTreeSet::new();
        for height in from_height..=to_height {
            for d in chain.deposits_at(height) {
                seen.insert(d.txid);
            }
        }
        for txid in &self.credited {
            if !seen.contains(txid) {
                return Err(WatcherError::CreditedDepositReorgedOut { txid: *txid });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A chain you can reorganise, which is the only interesting kind.
    #[derive(Default)]
    struct MockChain {
        blocks: BTreeMap<u64, Vec<ObservedDeposit>>,
        tip: u64,
    }

    impl MockChain {
        fn mine(&mut self, deposits: Vec<ObservedDeposit>) -> u64 {
            self.tip += 1;
            let h = self.tip;
            self.blocks.insert(
                h,
                deposits
                    .into_iter()
                    .map(|mut d| {
                        d.height = h;
                        d
                    })
                    .collect(),
            );
            h
        }
        fn mine_empty(&mut self, n: u64) {
            for _ in 0..n {
                self.mine(Vec::new());
            }
        }
        /// Roll back to `height` and mine a different history from there.
        fn reorg_to(&mut self, height: u64) {
            self.blocks.retain(|h, _| *h <= height);
            self.tip = height;
        }
    }

    impl ChainView for MockChain {
        fn tip(&self) -> u64 {
            self.tip
        }
        fn deposits_at(&self, height: u64) -> Vec<ObservedDeposit> {
            self.blocks.get(&height).cloned().unwrap_or_default()
        }
        fn balance_at(&self, height: u64) -> Option<Fixed> {
            if height > self.tip {
                return None;
            }
            let mut sum = Fixed::ZERO;
            for h in 1..=height {
                for d in self.blocks.get(&h).into_iter().flatten() {
                    sum = sum.add(d.amount)?;
                }
            }
            Some(sum)
        }
    }

    fn deposit(tag: u8, who: u8, amount: i64) -> ObservedDeposit {
        ObservedDeposit {
            txid: [tag; 32],
            account: [who; 32],
            amount: Fixed::whole(amount),
            height: 0,
            asset: None,
        }
    }

    fn credits(actions: &[WatcherAction]) -> Vec<(u64, [u8; 32])> {
        actions
            .iter()
            .filter_map(|a| match a {
                WatcherAction::Credit {
                    index,
                    external_ref,
                    ..
                } => Some((*index, *external_ref)),
                _ => None,
            })
            .collect()
    }

    /// Nothing is reported until it is buried, and then it is reported once.
    #[test]
    fn a_deposit_waits_for_its_confirmations() {
        let mut chain = MockChain::default();
        let mut w = Watcher::new(6, 1);
        chain.mine(vec![deposit(1, 9, 10)]);

        // One block deep, five to go.
        for _ in 0..5 {
            assert!(
                w.poll(&chain).unwrap().is_empty(),
                "reported before it was buried"
            );
            chain.mine_empty(1);
        }
        let actions = w.poll(&chain).unwrap();
        assert_eq!(credits(&actions), vec![(1, [1u8; 32])]);

        // And not again, however long the chain runs on.
        chain.mine_empty(20);
        assert!(
            w.poll(&chain).unwrap().is_empty(),
            "a deposit was reported twice"
        );
    }

    /// The observation always precedes the credits it covers, because the VM
    /// refuses to issue past the last observed balance.
    #[test]
    fn an_observation_comes_first_and_covers_what_follows() {
        let mut chain = MockChain::default();
        let mut w = Watcher::new(2, 1);
        chain.mine(vec![deposit(1, 9, 10), deposit(2, 8, 5)]);
        chain.mine_empty(2);

        let actions = w.poll(&chain).unwrap();
        let observed = match actions[0] {
            WatcherAction::Attest { observed } => observed,
            a => panic!("the first action was not an observation: {:?}", a),
        };
        let credited: Fixed = actions
            .iter()
            .filter_map(|a| match a {
                WatcherAction::Credit { amount, .. } => Some(*amount),
                _ => None,
            })
            .fold(Fixed::ZERO, |acc, x| acc.add(x).unwrap());
        assert_eq!(credited, Fixed::whole(15));
        assert!(
            observed >= credited,
            "the observation did not cover the credits"
        );
    }

    /// A deposit that is reorganised away before it is buried is never
    /// reported. This is what confirmation depth is for.
    #[test]
    fn a_deposit_reorged_out_before_confirmation_is_never_reported() {
        let mut chain = MockChain::default();
        let mut w = Watcher::new(6, 1);
        let h = chain.mine(vec![deposit(1, 9, 10)]);
        chain.mine_empty(3);
        assert!(w.poll(&chain).unwrap().is_empty());

        // The block is orphaned and a different history replaces it.
        chain.reorg_to(h - 1);
        chain.mine_empty(10);
        let actions = w.poll(&chain).unwrap();
        assert!(
            credits(&actions).is_empty(),
            "a vanished deposit was credited"
        );
        assert_eq!(
            w.next_index(),
            1,
            "an index was consumed by a deposit that never existed"
        );
    }

    /// A reorg that merely *moves* a deposit to a different block does not
    /// produce a second credit. Deduplication is by transaction, not by height.
    #[test]
    fn a_deposit_that_moves_blocks_is_not_credited_twice() {
        let mut chain = MockChain::default();
        let mut w = Watcher::new(2, 1);
        chain.mine(vec![deposit(1, 9, 10)]);
        chain.mine_empty(2);
        assert_eq!(credits(&w.poll(&chain).unwrap()).len(), 1);

        // Same transaction, re-mined higher up after a reorg.
        chain.reorg_to(1);
        chain.mine(vec![deposit(1, 9, 10)]);
        chain.mine_empty(5);
        assert!(
            credits(&w.poll(&chain).unwrap()).is_empty(),
            "a moved deposit was re-credited"
        );
        assert_eq!(w.next_index(), 2);
    }

    /// Indices are strictly sequential with no gaps, because the VM refuses
    /// both a repeat and a gap.
    #[test]
    fn indices_are_dense_and_in_order() {
        let mut chain = MockChain::default();
        let mut w = Watcher::new(1, 1);
        let mut all = Vec::new();
        for round in 0..10u8 {
            chain.mine(vec![deposit(round * 2, 1, 1), deposit(round * 2 + 1, 2, 1)]);
            all.extend(credits(&w.poll(&chain).unwrap()));
        }
        assert_eq!(all.len(), 20);
        for (i, (index, _)) in all.iter().enumerate() {
            assert_eq!(*index, i as u64 + 1, "indices are not dense");
        }
    }

    /// Two watchers scanning the same chain must assign the same indices to the
    /// same transactions, or they disagree about what the chain says.
    #[test]
    fn two_watchers_agree() {
        let mut chain = MockChain::default();
        chain.mine(vec![deposit(3, 1, 1), deposit(1, 2, 2), deposit(2, 3, 3)]);
        chain.mine(vec![deposit(5, 1, 1), deposit(4, 2, 2)]);
        chain.mine_empty(3);

        let mut a = Watcher::new(2, 1);
        let mut b = Watcher::new(2, 1);
        assert_eq!(
            credits(&a.poll(&chain).unwrap()),
            credits(&b.poll(&chain).unwrap())
        );
    }

    /// A chain that cannot answer makes the watcher stand still rather than
    /// skip. A partial scan that advanced would lose the heights it failed on.
    #[test]
    fn an_unavailable_chain_costs_no_progress() {
        struct Broken(MockChain);
        impl ChainView for Broken {
            fn tip(&self) -> u64 {
                self.0.tip()
            }
            fn deposits_at(&self, h: u64) -> Vec<ObservedDeposit> {
                self.0.deposits_at(h)
            }
            fn balance_at(&self, _: u64) -> Option<Fixed> {
                None
            }
        }
        let mut inner = MockChain::default();
        inner.mine(vec![deposit(1, 9, 10)]);
        inner.mine_empty(4);
        let chain = Broken(inner);

        let mut w = Watcher::new(2, 1);
        assert_eq!(w.poll(&chain), Err(WatcherError::Unavailable));
        assert_eq!(w.scanned_to(), 0, "a failed poll advanced the scan");
        assert_eq!(w.next_index(), 1, "a failed poll consumed an index");
    }

    /// The alarm: a deposit already credited is gone from the chain. Units
    /// exist that nothing backs, and no amount of watching repairs it.
    #[test]
    fn a_credited_deposit_vanishing_is_an_alarm_not_a_retry() {
        let mut chain = MockChain::default();
        let mut w = Watcher::new(2, 1);
        chain.mine(vec![deposit(1, 9, 10)]);
        chain.mine_empty(3);
        assert_eq!(credits(&w.poll(&chain).unwrap()).len(), 1);
        w.audit(&chain, 1, chain.tip()).expect("still there");

        // A reorg deeper than the confirmation depth. Improbable, not
        // impossible — and the only useful thing code can do is name it.
        chain.reorg_to(0);
        chain.mine_empty(10);
        assert_eq!(
            w.audit(&chain, 1, chain.tip()),
            Err(WatcherError::CreditedDepositReorgedOut { txid: [1u8; 32] })
        );
    }

    #[test]
    fn a_chain_shorter_than_the_confirmation_depth_reports_nothing() {
        let mut chain = MockChain::default();
        let mut w = Watcher::new(100, 1);
        chain.mine(vec![deposit(1, 9, 10)]);
        chain.mine_empty(5);
        assert!(w.poll(&chain).unwrap().is_empty());
        assert_eq!(w.scanned_to(), 0);
    }

    /// A zero-value note is not a deposit, and must not consume an index the VM
    /// would then expect to see used.
    #[test]
    fn a_zero_deposit_is_ignored() {
        let mut chain = MockChain::default();
        let mut w = Watcher::new(1, 1);
        chain.mine(vec![deposit(1, 9, 0), deposit(2, 9, 5)]);
        let actions = w.poll(&chain).unwrap();
        assert_eq!(credits(&actions), vec![(1, [2u8; 32])]);
        assert_eq!(w.next_index(), 2);
    }
}

#[cfg(test)]
mod finality_model_tests {
    //! Not every chain measures finality in depth.
    //!
    //! Zcash and Bitcoin do: a block is safe when enough blocks sit on top.
    //! Ed25519 does not — it has commitment levels, and `finalized` is
    //! supermajority-voted rather than probabilistic.
    //!
    //! The trait still fits, and this pins down why: a chain with explicit
    //! finality reports its **finalized** height as the tip and asks for zero
    //! confirmations. The depth model is not wrong there, it is unnecessary,
    //! and the degenerate case has to actually work or the abstraction would
    //! need replacing before the second bridge.

    use super::*;
    use crate::amount::Fixed;

    struct Chain {
        tip: u64,
        deposits: Vec<ObservedDeposit>,
    }

    impl ChainView for Chain {
        fn tip(&self) -> u64 {
            self.tip
        }
        fn deposits_at(&self, height: u64) -> Vec<ObservedDeposit> {
            self.deposits
                .iter()
                .filter(|d| d.height == height)
                .cloned()
                .collect()
        }
        fn balance_at(&self, height: u64) -> Option<Fixed> {
            Some(
                self.deposits
                    .iter()
                    .filter(|d| d.height <= height)
                    .fold(Fixed::ZERO, |a, d| a.add(d.amount).unwrap()),
            )
        }
    }

    fn deposit(height: u64, n: u8) -> ObservedDeposit {
        ObservedDeposit {
            txid: [n; 32],
            account: [n; 32],
            amount: Fixed::whole(n as i64),
            height,
            asset: None,
        }
    }

    /// A chain whose tip is already final credits it immediately.
    #[test]
    fn zero_confirmations_credits_a_finalized_tip() {
        let chain = Chain {
            tip: 100,
            deposits: vec![deposit(100, 1)],
        };
        let mut w = Watcher::new(0, 1);
        let actions = w.poll(&chain).expect("poll");
        assert_eq!(actions.len(), 2, "an attestation and one credit");
        assert!(matches!(actions[0], WatcherAction::Attest { .. }));
    }

    /// And the depth model still holds back what is not yet deep enough, so
    /// one trait serves both without a flag deciding which chain it is.
    #[test]
    fn depth_still_holds_back_a_shallow_deposit() {
        let chain = Chain {
            tip: 102,
            deposits: vec![deposit(100, 1)],
        };
        let mut w = Watcher::new(6, 1);
        assert!(
            w.poll(&chain).expect("poll").is_empty(),
            "credited at two deep"
        );

        let deeper = Chain {
            tip: 106,
            deposits: vec![deposit(100, 1)],
        };
        assert_eq!(w.poll(&deeper).expect("poll").len(), 2);
    }
}
