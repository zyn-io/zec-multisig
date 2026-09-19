//! Building the transaction that pays a withdrawal.
//!
//! The last piece of custody, and the one everything else was for. A deposit
//! that cannot be reversed is not custody, it is a donation.
//!
//! # The shape of a payout
//!
//! ```text
//!   notes            which the vault holds          crate::notes
//!   anchor + paths   proved against a real root     crate::notes
//!   bundle           actions, and a proof           orchard::builder
//!   sighash          what the signers authorise     this module
//!   signatures       k-of-n, re-randomized          crate::signing::orchard
//!   broadcast        send_raw_transaction           crate::zebra
//! ```
//!
//! # Two pools, two kinds of exit
//!
//! Since NU6.3 a vault holds notes in two pools with the same keys. From the
//! **Ironwood** pool an exit pays a shielded address directly, in a v6
//! transaction — cross-address outputs are permitted there. From the
//! **Orchard** pool it cannot (below), and the exit is transparent. The pool
//! is chosen by where the notes are; the recipient's address type decides
//! what the payout may contain.
//!
//! # Where the money goes: transparent, under NU6.3
//!
//! At NU6.3 (testnet 4,134,000) the Orchard pool **forbids cross-address
//! transfers**: every action's spend and output must belong to the same
//! receiver, by consensus. Paying another shielded address from an Orchard
//! note is not restricted, it is unrepresentable — the builder refuses it
//! (`CrossAddressDisabled`), and so would the network. That freedom moved to
//! the Ironwood pool, which needs v6 transactions.
//!
//! What an Orchard vault *can* still do is leave the pool through the value
//! balance. So a payout spends the vault's notes, returns change to the
//! vault's own receiver (the one same-address output the rules allow) and
//! pays the recipient a **transparent** output. The exit is public on the
//! chain; the trading that preceded it was not. `DECISIONS` §17 records the
//! trade and the Ironwood path out of it.
//!
//! # Why the signing step is separated
//!
//! `orchard`'s builder can sign for you if you hand it a `SpendAuthorizingKey`.
//! The vault has no such thing: the spending authority is split across a signer
//! set and exists nowhere as one value, which is the entire point of the
//! ceremony.
//!
//! So this stops at the sighash, hands out what the signers need, and takes
//! signatures back. Each action carries its own `alpha`, and a signature is
//! produced under `rk = ak + alpha·G` — see `crate::signing::orchard` for why
//! plain FROST would silently produce the wrong thing.

use frost_rerandomized::Randomizer;
use orchard::builder::{Builder, BundleType};
use orchard::bundle::BundleVersion;
use orchard::circuit::ProvingKey;
use orchard::keys::{FullViewingKey, OutgoingViewingKey};
use orchard::primitives::redpallas;
use orchard::value::NoteValue;
use orchard::ValuePool;
use orchard::{Address, Anchor};
use reddsa::frost::redpallas::PallasBlake2b512;
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::{TransparentBuilder, Unauthorized as TransparentUnauthorized};
use zcash_transparent::bundle::{Authorized as TransparentAuthorized, Bundle as TransparentBundle};

use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{
    Authorization, Authorized as TxAuthorized, TransactionData, TxVersion,
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network, NetworkUpgrade, Parameters};
use zcash_protocol::value::ZatBalance;

use crate::ceremony::Identifier;
use crate::notes::{HeldNote, NoteError, NoteStore};
use crate::signing::VaultKeys;

#[derive(Debug)]
pub enum PayoutError {
    /// The transaction around the bundle could not be formed or serialised.
    Envelope(String),
    /// The vault cannot cover the payment.
    Notes(NoteError),
    /// `orchard` refused to build. Not something to work around.
    Build(String),
    /// A signature did not authorise the action it was offered for.
    ///
    /// Reported rather than retried: a wrong signature means the signers and
    /// the builder disagree about what is being signed, and sending it again
    /// cannot resolve a disagreement.
    BadSignature,
    /// A signature arrived for an action the bundle does not have.
    NoSuchAction(usize),
}

impl From<NoteError> for PayoutError {
    fn from(e: NoteError) -> Self {
        PayoutError::Notes(e)
    }
}

impl std::fmt::Display for PayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayoutError::Envelope(e) => write!(f, "transaction envelope: {}", e),
            PayoutError::Notes(e) => write!(f, "the vault cannot pay this: {:?}", e),
            PayoutError::Build(m) => write!(f, "orchard refused to build: {}", m),
            PayoutError::BadSignature => {
                write!(
                    f,
                    "a signature did not authorise the action it was given for"
                )
            }
            PayoutError::NoSuchAction(i) => write!(f, "no action {} in this bundle", i),
        }
    }
}

/// One recipient of a payout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Payment {
    pub to: Destination,
    pub zatoshi: u64,
    /// Carried only by a shielded output. A deposit into a Zyn vault names
    /// its account here (`crate::memo`).
    pub memo: [u8; 512],
}

impl Payment {
    pub fn new(to: Destination, zatoshi: u64) -> Payment {
        Payment {
            to,
            zatoshi,
            memo: [0u8; 512],
        }
    }
}

/// Where a payout may go.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Destination {
    /// Any pool can pay this, through the value balance.
    Transparent(TransparentAddress),
    /// Only the Ironwood pool can pay this (an Orchard/Ironwood receiver).
    Shielded(Address),
}

/// One action waiting on the signer set.
///
/// `alpha` is why this type exists. Each action is authorised under
/// `rk = ak + alpha·G`, and a signer that does not receive `alpha` cannot
/// produce a signature the action accepts — see `crate::signing::orchard`.
pub struct NeedsSignature {
    pub index: usize,
    pub alpha: Randomizer<PallasBlake2b512>,
    /// The key the signature must verify under. The coordinator can check a
    /// signature against this before sending it anywhere.
    pub rk: redpallas::VerificationKey<redpallas::SpendAuth>,
}

/// A payout assembled and waiting for authorisation.
///
/// Built as a **PCZT** rather than through the ordinary bundle path, and not
/// for the usual reason. `orchard`'s `Builder` keeps each action's `alpha`
/// private, so it can only sign with a key held locally — which the vault by
/// construction does not have. The PCZT exposes `alpha` and `rk`, which is
/// exactly what a threshold signer needs and the only route to one.
pub struct Payout {
    bundle: orchard::pczt::Bundle,
    transparent: Option<TransparentBundle<TransparentUnauthorized>>,
    spent: Vec<HeldNote>,
    pub fee: u64,
    pub pool: ValuePool,
}

impl Payout {
    /// What the signer set has to authorise.
    ///
    /// **Only the vault's own actions.** A bundle is padded with dummy actions
    /// to hide how many real spends it contains — that padding is a privacy
    /// feature, and each dummy carries its own randomizer and its own key,
    /// already signed by the builder. Handing those to the signer set would
    /// ask it to authorise spends of notes it does not own, and the signatures
    /// would be rejected.
    ///
    /// The filter is `rk == group_key.randomize(alpha)`, which is the same
    /// comparison `Action::sign` makes internally. So a signer is not merely
    /// told which actions are the vault's — it can check.
    pub fn needs_signatures(
        &self,
        group_key: &reddsa::frost::redpallas::VerifyingKey,
    ) -> Vec<NeedsSignature> {
        self.bundle
            .actions()
            .iter()
            .enumerate()
            .filter_map(|(index, a)| {
                let alpha = Randomizer::from_scalar((*a.spend().alpha())?);
                let expected =
                    frost_rerandomized::RandomizedParams::from_randomizer(group_key, alpha)
                        .randomized_verifying_key()
                        .serialize()
                        .ok()?;
                let rk = a.spend().rk().clone();
                if <[u8; 32]>::from(&rk).as_slice() != expected.as_slice() {
                    return None; // padding, or somebody else's note
                }
                Some(NeedsSignature { index, alpha, rk })
            })
            .collect()
    }

    /// Attach one action's signature.
    ///
    /// `orchard` verifies it against the action's `rk` before accepting, so a
    /// signature produced under the wrong randomizer — or by the wrong signer
    /// set — is refused here rather than by the network.
    pub fn apply(
        &mut self,
        index: usize,
        sighash: [u8; 32],
        signature: redpallas::Signature<redpallas::SpendAuth>,
    ) -> Result<(), PayoutError> {
        let action = self
            .bundle
            .actions_mut()
            .get_mut(index)
            .ok_or(PayoutError::NoSuchAction(index))?;
        action
            .apply_signature(sighash, signature)
            .map_err(|_| PayoutError::BadSignature)
    }

    /// The notes this payout consumes.
    ///
    /// Returned rather than removed when the bundle was built, so the store
    /// forgets them once the transaction is broadcast and **only** then — a
    /// payout that failed to sign has not spent anything.
    pub fn spent(&self) -> &[HeldNote] {
        &self.spent
    }

    pub fn bundle(&self) -> &orchard::pczt::Bundle {
        &self.bundle
    }
}

/// Assemble a payout for the signer set to authorise.
/// ZIP-317: a flat marginal fee per logical action, with a floor of two.
pub fn zip317_fee(shielded_actions: usize, transparent_outputs: usize) -> u64 {
    5_000 * (shielded_actions + transparent_outputs).max(2) as u64
}

/// Assemble a payout for the signer set to authorise.
///
/// `version` must be the one the chain expects at broadcast — take it from
/// [`Envelope::bundle_version`] — because it fixes the circuit, the note
/// version and whether cross-address outputs may exist at all.
#[allow(clippy::too_many_arguments)]
pub fn build(
    store: &NoteStore,
    fvk: &FullViewingKey,
    ovk: Option<OutgoingViewingKey>,
    payments: &[Payment],
    change_to: Address,
    version: BundleVersion,
    mut rng: impl rand::RngCore + rand::CryptoRng,
) -> Result<Payout, PayoutError> {
    if payments.is_empty() {
        return Err(PayoutError::Build("nothing to pay".into()));
    }
    let owed: u64 = payments.iter().map(|p| p.zatoshi).sum();
    let shielded_out = payments
        .iter()
        .filter(|p| matches!(p.to, Destination::Shielded(_)))
        .count();
    let transparent_out = payments.len() - shielded_out;
    if shielded_out > 0 && !version.default_flags().cross_address_enabled() {
        return Err(PayoutError::Build(
            "this pool cannot pay a shielded address (NU6.3 Orchard restriction)".into(),
        ));
    }
    // The fee depends on the action count, which depends on whether there is
    // change, which depends on the fee. Two passes settle it.
    let mut fee = zip317_fee(2, transparent_out);
    for _ in 0..2 {
        let spent = store.select(owed + fee)?;
        let held: u64 = spent.iter().map(HeldNote::value).sum();
        let change = held - owed - fee;
        let outputs = shielded_out + usize::from(change > 0);
        // Under the restriction each spend and each output sit in their own
        // action; without it the builder pairs spends with outputs.
        let actions = if version.default_flags().cross_address_enabled() {
            spent.len().max(outputs)
        } else {
            spent.len() + outputs
        };
        let needed = zip317_fee(actions.max(2), transparent_out);
        if needed != fee {
            fee = needed;
            continue;
        }
        return assemble(
            store,
            fvk,
            ovk.clone(),
            payments,
            change_to,
            version,
            spent,
            change,
            fee,
            &mut rng,
        );
    }
    Err(PayoutError::Build("fee did not converge".into()))
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    store: &NoteStore,
    fvk: &FullViewingKey,
    ovk: Option<OutgoingViewingKey>,
    payments: &[Payment],
    change_to: Address,
    version: BundleVersion,
    spent: Vec<HeldNote>,
    change: u64,
    fee: u64,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<Payout, PayoutError> {
    let anchor: Anchor = store.anchor()?;
    let mut builder = Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        anchor,
    )
    .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;
    for n in &spent {
        let path = store.witness(n.position)?;
        builder
            .add_spend(fvk.clone(), n.note, path)
            .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;
    }
    // Shielded recipients, where the pool permits them.
    for p in payments {
        if let Destination::Shielded(to) = p.to {
            builder
                .add_output(ovk.clone(), to, NoteValue::from_raw(p.zatoshi), p.memo)
                .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;
        }
    }
    // Change back to the vault's own receiver — under the restriction the one
    // output the rules allow, and always the difference between "change" and
    // "an accidental fee".
    if change > 0 {
        builder
            .add_change_output(
                fvk.clone(),
                ovk,
                change_to,
                NoteValue::from_raw(change),
                [0u8; 512],
            )
            .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;
    }
    let (bundle, _meta) = builder
        .build_for_pczt(&mut *rng)
        .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;

    let mut t = TransparentBuilder::empty();
    for p in payments {
        if let Destination::Transparent(to) = p.to {
            let value =
                Zatoshis::from_u64(p.zatoshi).map_err(|_| PayoutError::Build("amount".into()))?;
            t.add_output(&to, value)
                .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;
        }
    }
    Ok(Payout {
        bundle,
        transparent: t.build(),
        spent,
        fee,
        pool: version.value_pool(),
    })
}

/// The transaction around the bundle: a v5 transaction carrying the Orchard
/// bundle and the transparent outputs it pays.
///
/// A payout has no transparent inputs, no Sapling, no Sprout — so the "rest
/// of the transaction" is a version, a consensus branch, a lock time of zero
/// and an expiry. Those still commit into the sighash (ZIP-244), which is why
/// they are fixed *before* the signers see anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Envelope {
    pub branch: BranchId,
    /// The transaction is invalid from this height on. A payout that did not
    /// land by then can be rebuilt without fear of both landing.
    pub expiry: BlockHeight,
}

/// Blocks a payout stays valid after it is built. zcashd's default.
pub const EXPIRY_DELTA: u32 = 40;

impl Envelope {
    /// For a transaction built at `height` on `network`.
    pub fn at(network: Network, height: u32) -> Envelope {
        let h = BlockHeight::from_u32(height);
        Envelope {
            branch: BranchId::for_height(&network, h),
            expiry: h + EXPIRY_DELTA,
        }
    }

    /// The Orchard bundle version the chain expects under this branch.
    pub fn bundle_version(&self) -> Result<BundleVersion, PayoutError> {
        self.bundle_version_for(ValuePool::Orchard)
    }

    /// The bundle version for a pool under this branch. `None` from the
    /// library means the pool does not exist yet — Ironwood before NU6.3.
    pub fn bundle_version_for(&self, pool: ValuePool) -> Result<BundleVersion, PayoutError> {
        bundle_version_for_branch(self.branch, pool).ok_or_else(|| {
            PayoutError::Envelope(format!("no {:?} pool under {:?}", pool, self.branch))
        })
    }

    pub fn testnet_at(height: u32) -> Envelope {
        Envelope::at(Network::TestNetwork, height)
    }

    /// Whether NU5 is active — an Orchard bundle cannot exist before it.
    pub fn orchard_is_live(network: Network, height: u32) -> bool {
        network
            .activation_height(NetworkUpgrade::Nu5)
            .map(|a| BlockHeight::from_u32(height) >= a)
            .unwrap_or(false)
    }
}

/// The transaction with effects but no authorization — what a sighash is
/// computed over.
/// A transaction carrying only what a sighash is taken over. Public so the
/// transparent sweep can build the same shape; nothing else should need it.
pub struct Effects;

impl Authorization for Effects {
    type TransparentAuth = TransparentUnauthorized;
    type SaplingAuth = sapling_crypto::bundle::Authorized;
    type OrchardAuth = orchard::bundle::EffectsOnly;
}

/// A finished transaction, ready for `sendrawtransaction`.
pub struct Sealed {
    pub txid: [u8; 32],
    pub bytes: Vec<u8>,
    /// The notes it spends. Forget them from the store once it is broadcast.
    pub spent: Vec<HeldNote>,
}

impl Sealed {
    /// The txid as a node displays it: byte-reversed hex.
    pub fn txid_hex(&self) -> String {
        self.txid
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
    pub fn hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl Payout {
    /// The sighash every signer authorises: ZIP-244 over the whole v5
    /// transaction.
    pub fn sighash(&self, env: &Envelope) -> Result<[u8; 32], PayoutError> {
        let effects = self
            .bundle
            .extract_effects::<ZatBalance>()
            .map_err(|e| PayoutError::Envelope(format!("{:?}", e)))?;
        let tx = match self.pool {
            ValuePool::Orchard => TransactionData::<Effects>::from_parts(
                TxVersion::V5,
                env.branch,
                0,
                env.expiry,
                self.transparent.clone(),
                None,
                None,
                effects,
            ),
            // Ironwood exists only in v6 transactions.
            ValuePool::Ironwood => TransactionData::<Effects>::from_parts_v6(
                env.branch,
                0,
                env.expiry,
                self.transparent.clone(),
                None,
                None,
                effects,
            ),
        };
        let digests = tx.digest(TxIdDigester);
        Ok(*signature_hash(&tx, &SignableInput::Shielded, &digests).as_ref())
    }

    /// Fix the bundle's value balance and sign its **dummy** spends.
    ///
    /// Padding actions carry keys the builder made up; those are signed here,
    /// under the same sighash the real ones will be. Must precede the proof
    /// and the signer set.
    pub fn finalize_io(
        &mut self,
        sighash: [u8; 32],
        rng: impl rand::RngCore + rand::CryptoRng,
    ) -> Result<(), PayoutError> {
        self.bundle
            .finalize_io(sighash, rng)
            .map_err(|e| PayoutError::Envelope(format!("{:?}", e)))
    }

    /// The zero-knowledge proof. Seconds, and standard.
    pub fn prove(
        &mut self,
        pk: &ProvingKey,
        rng: impl rand::RngCore + rand::CryptoRng,
    ) -> Result<(), PayoutError> {
        self.bundle
            .create_proof(pk, rng)
            .map_err(|e| PayoutError::Envelope(format!("{:?}", e)))
    }

    /// Seal: every action signed, the bundle bound, the transaction
    /// serialised.
    ///
    /// `apply_binding_signature` re-verifies every spend signature against
    /// `sighash` first, so a bundle with one bad action fails here, before
    /// anything is sent.
    pub fn extract(
        self,
        sighash: [u8; 32],
        env: &Envelope,
        rng: impl rand::RngCore + rand::CryptoRng,
    ) -> Result<Sealed, PayoutError> {
        let unbound = self
            .bundle
            .extract::<ZatBalance>()
            .map_err(|e| PayoutError::Envelope(format!("{:?}", e)))?
            .ok_or_else(|| PayoutError::Envelope("no actions".into()))?;
        let authorized = unbound
            .apply_binding_signature(sighash, rng)
            .ok_or(PayoutError::BadSignature)?;
        // No transparent inputs, so nothing to sign on that side: the
        // authorized bundle is the outputs and a unit marker.
        let transparent = self.transparent.as_ref().map(|t| TransparentBundle {
            vin: Vec::new(),
            vout: t.vout.clone(),
            authorization: TransparentAuthorized,
        });
        let tx = match self.pool {
            ValuePool::Orchard => TransactionData::<TxAuthorized>::from_parts(
                TxVersion::V5,
                env.branch,
                0,
                env.expiry,
                transparent,
                None,
                None,
                Some(authorized),
            ),
            ValuePool::Ironwood => TransactionData::<TxAuthorized>::from_parts_v6(
                env.branch,
                0,
                env.expiry,
                transparent,
                None,
                None,
                Some(authorized),
            ),
        }
        .freeze()
        .map_err(|e| PayoutError::Envelope(e.to_string()))?;
        let mut bytes = Vec::new();
        tx.write(&mut bytes)
            .map_err(|e| PayoutError::Envelope(e.to_string()))?;
        Ok(Sealed {
            txid: *tx.txid().as_ref(),
            bytes,
            spent: self.spent,
        })
    }
}

/// Parse a transparent address (`t1…`/`t3…` on mainnet, `tm…`/`t2…` on
/// testnet) for the given network.
///
/// Base58check by hand: the address is twenty bytes behind a two-byte prefix
/// and a four-byte checksum, and getting it wrong pays the wrong person, so
/// the checksum is not optional.
pub fn transparent_address(s: &str, network: Network) -> Option<TransparentAddress> {
    let raw = crate::base58::base58_decode(s)?;
    if raw.len() != 26 {
        return None;
    }
    let (body, check) = raw.split_at(22);
    use sha2::Digest;
    let h = sha2::Sha256::digest(sha2::Sha256::digest(body));
    if h[..4] != *check {
        return None;
    }
    let (p2pkh, p2sh): ([u8; 2], [u8; 2]) = match network {
        Network::MainNetwork => ([0x1C, 0xB8], [0x1C, 0xBD]),
        Network::TestNetwork => ([0x1D, 0x25], [0x1C, 0xBA]),
    };
    let hash: [u8; 20] = body[2..].try_into().ok()?;
    if body[..2] == p2pkh {
        Some(TransparentAddress::PublicKeyHash(hash))
    } else if body[..2] == p2sh {
        Some(TransparentAddress::ScriptHash(hash))
    } else {
        None
    }
}

/// Authorise with an ordinary spending key — a wallet, not a vault.
///
/// Every action whose randomised key derives from `ask` is signed; the rest
/// (padding, already signed by the builder) are left alone. Returns how many
/// were signed.
pub fn sign_with_key(
    payout: &mut Payout,
    sighash: [u8; 32],
    ask: &orchard::keys::SpendAuthorizingKey,
    mut rng: impl rand::RngCore + rand::CryptoRng,
) -> usize {
    let mut signed = 0;
    for action in payout.bundle.actions_mut() {
        if action.sign(sighash, ask, &mut rng).is_ok() {
            signed += 1;
        }
    }
    signed
}

/// Authorise every one of the vault's actions with a quorum, in-process.
///
/// Both FROST rounds per action, each under that action's own randomizer —
/// the loop the tests drive, made the library's so the operator cannot drive
/// it differently. A real deployment runs the same sequence with messages
/// between machines. Returns how many actions were signed.
pub fn sign_all(
    payout: &mut Payout,
    sighash: [u8; 32],
    keys: &[(Identifier, &VaultKeys)],
    threshold: u16,
    mut _rng: impl rand::RngCore + rand::CryptoRng,
) -> Result<usize, PayoutError> {
    // The in-process quorum: the V0 path, unchanged behaviour, now expressed
    // through the same abstraction a distributed quorum uses.
    let group = keys
        .first()
        .ok_or(PayoutError::BadSignature)?
        .1
        .public_package
        .verifying_key();
    let public = keys.first().unwrap().1.public_package.clone();
    let mut quorum =
        crate::signing::LocalQuorum::new(keys.iter().map(|(_, k)| (*k).clone()).collect());
    sign_all_with(payout, sighash, &mut quorum, threshold, &group, &public, 0)
}

/// Sign every action the vault owns by driving a [`crate::signing::Quorum`] —
/// local or remote — through the two rounds. The coordinator holds no share:
/// it needs only the group key and the public package, both public.
///
/// Two round trips for the whole payout, not two per action: round one gets a
/// commitment per action from each participant, round two a share per action.
pub fn sign_all_with(
    payout: &mut Payout,
    sighash: [u8; 32],
    quorum: &mut dyn crate::signing::Quorum,
    threshold: u16,
    group: &reddsa::frost::redpallas::VerifyingKey,
    public: &reddsa::frost::redpallas::keys::PublicKeyPackage,
    now: u64,
) -> Result<usize, PayoutError> {
    use crate::signing::orchard::{aggregate, params_for, to_spend_auth};
    let needed = payout.needs_signatures(group);
    if needed.is_empty() {
        return Ok(0);
    }
    let alphas: Vec<_> = needed.iter().map(|n| n.alpha).collect();
    // A request id fresh per attempt, so a retry never collides with nonces a
    // custodian may still hold from a previous one.
    let request_id: u64 = rand::RngCore::next_u64(&mut rand::rngs::OsRng);

    // Round one: collect commitments; keep a threshold of whoever answered.
    let r1 = quorum.round1(request_id, sighash, &alphas, now);
    if r1.len() < usize::from(threshold) {
        return Err(PayoutError::BadSignature);
    }
    let chosen: Vec<Identifier> = r1.keys().take(usize::from(threshold)).copied().collect();

    // One package per action, from the chosen participants' i-th commitments.
    let mut packages = Vec::with_capacity(alphas.len());
    for i in 0..alphas.len() {
        let mut commitments = std::collections::BTreeMap::new();
        for id in &chosen {
            let per_action = r1.get(id).ok_or(PayoutError::BadSignature)?;
            commitments.insert(*id, *per_action.get(i).ok_or(PayoutError::BadSignature)?);
        }
        packages.push(frost_core::SigningPackage::new(commitments, &sighash));
    }

    // Round two: the chosen participants each return a share per action.
    let r2 = quorum.round2(request_id, &chosen, &packages);
    if r2.len() < usize::from(threshold) {
        return Err(PayoutError::BadSignature);
    }

    for (i, n) in needed.iter().enumerate() {
        let mut shares = std::collections::BTreeMap::new();
        for id in &chosen {
            let per_action = r2.get(id).ok_or(PayoutError::BadSignature)?;
            shares.insert(
                *id,
                per_action.get(i).ok_or(PayoutError::BadSignature)?.clone(),
            );
        }
        let params = params_for(group, n.alpha);
        let sig = aggregate(&packages[i], &shares, public, &params)
            .map_err(|_| PayoutError::BadSignature)?;
        payout.apply(
            n.index,
            sighash,
            to_spend_auth(&sig).map_err(|_| PayoutError::BadSignature)?,
        )?;
    }
    Ok(needed.len())
}

/// Build the proving key.
///
/// Seconds of work and hundreds of megabytes, so a process builds one and keeps
/// it. It depends on nothing but the circuit version — no secrets, no vault —
/// which is why it can be shared, cached, or shipped.
pub fn proving_key(version: BundleVersion) -> ProvingKey {
    ProvingKey::build(version.circuit_version())
}

/// The circuit is a property of the bundle version: v2 is the post-NU6.2
/// fixed circuit, v3 the NU6.3 one. Proving under the other produces a proof
/// that constructs fine and fails to verify — which is how this was found.
pub fn verifying_key(version: BundleVersion) -> orchard::circuit::VerifyingKey {
    orchard::circuit::VerifyingKey::build(version.circuit_version())
}

#[cfg(test)]
mod tests {
    //! The whole custody path, minus the network.
    //!
    //! A vault holds notes it found; a withdrawal is assembled against a real
    //! anchor; the signer set authorises every action without any one of them
    //! holding a spending key; and `orchard` accepts the result.
    //!
    //! No proof is generated here, and that is not a shortcut:
    //! `apply_signature` checks a signature against the action's `rk` and
    //! nothing else, so this exercises exactly the step that could be wrong.
    //! The proof is expensive, standard, and `orchard`'s to get right.

    use super::*;
    use crate::ceremony::Ceremony;
    use crate::notes::NoteStore;
    use crate::signing::{
        orchard::{aggregate, params_for, sign_share, to_spend_auth},
        Coordinator, SigningSession,
    };
    use orchard::keys::{Scope, SpendingKey};
    use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
    use orchard::Note;
    use reddsa::frost::redpallas::Identifier;
    use std::collections::BTreeMap;

    /// A vault whose Orchard identity **is** the signer set's key, holding one
    /// note of `value`, with the tree that proves it.
    ///
    /// The derivation is the point. A vault built from an ordinary spending key
    /// would receive notes the threshold cannot authorise — and every test
    /// short of an actual signature would still pass.
    fn funded_vault(
        value: u64,
        keys: &[(Identifier, crate::ceremony::VaultKeys)],
    ) -> (NoteStore, FullViewingKey, Address) {
        funded_vault_v(value, keys, NoteVersion::V2)
    }

    fn funded_vault_v(
        value: u64,
        keys: &[(Identifier, crate::ceremony::VaultKeys)],
        note_version: NoteVersion,
    ) -> (NoteStore, FullViewingKey, Address) {
        let group = keys[0].1.group_key();
        let fvk = (0u8..64)
            .find_map(|n| crate::ceremony::orchard_viewing_key(&group, [n; 32], [n; 32]))
            .expect("a valid (nk, rivk)");
        let recipient = fvk.address_at(0u32, Scope::External);

        let rho = Rho::from_bytes(&[5u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([6u8; 32], &rho).unwrap();
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            rseed,
            note_version,
        )
        .unwrap();

        let mut store = NoteStore::new();
        store.begin_block(1);
        // Somebody else's output first, so our note is not at position zero —
        // a path that only works at the start of the tree is not a path.
        let other = {
            let osk = SpendingKey::from_bytes([9u8; 32]).unwrap();
            let ofvk = FullViewingKey::from(&osk);
            let orho = Rho::from_bytes(&[8u8; 32]).unwrap();
            let orseed = RandomSeed::from_bytes([7u8; 32], &orho).unwrap();
            Note::from_parts(
                ofvk.address_at(0u32, Scope::External),
                NoteValue::from_raw(1),
                orho,
                orseed,
                note_version,
            )
            .unwrap()
        };
        store.append(&ExtractedNoteCommitment::from(other.commitment()), false);

        let pos = store
            .append(&ExtractedNoteCommitment::from(note.commitment()), true)
            .expect("our commitment is marked");
        store.hold(note, pos, 1, [1u8; 32]);
        (store, fvk, recipient)
    }

    /// Somewhere for the money to go.
    fn a_recipient() -> Destination {
        Destination::Transparent(TransparentAddress::PublicKeyHash([42u8; 20]))
    }
    fn v3() -> BundleVersion {
        Envelope::testnet_at(4_300_000).bundle_version().unwrap()
    }

    #[test]
    fn the_signer_set_authorises_a_withdrawal() {
        // The vault holds the spending key nowhere: 2 of 3 shares.
        let keys: Vec<(Identifier, crate::ceremony::VaultKeys)> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .collect();
        let (store, fvk, change_to) = funded_vault(100_000, &keys);
        let mut payout = build(
            &store,
            &fvk,
            None,
            &[Payment::new(a_recipient(), 400)],
            change_to,
            v3(),
            rand::rngs::OsRng,
        )
        .expect("the vault can afford this");

        let sighash = [0x11u8; 32]; // the transaction's, in production
        let needed = payout.needs_signatures(keys[0].1.public_package.verifying_key());
        // Two, not one: under the cross-address restriction the change sits in
        // its own action, whose spend is a zero-value note at the vault's own
        // address — keyed to the vault, so the threshold authorises it too.
        assert_eq!(
            needed.len(),
            2,
            "the real spend and the change action's spend"
        );

        for n in needed {
            // Round one.
            let sessions: Vec<SigningSession> = keys
                .iter()
                .take(2)
                .map(|(id, k)| SigningSession::begin(*id, k, &mut rand::rngs::OsRng))
                .collect();
            let mut coord = Coordinator::new(sighash.to_vec(), 2);
            for s in &sessions {
                coord.add_commitment(s.id(), s.commitments());
            }
            let package = coord.package().expect("a signing package");

            // Round two, under *this action's* randomizer.
            let mut shares = BTreeMap::new();
            for (s, (_, k)) in sessions.into_iter().zip(keys.iter()) {
                let id = s.id();
                shares.insert(id, sign_share(s, k, &package, n.alpha).expect("a share"));
            }
            let params = params_for(keys[0].1.public_package.verifying_key(), n.alpha);
            let sig = aggregate(&package, &shares, &keys[0].1.public_package, &params)
                .expect("aggregation");

            // The coordinator can check before sending it anywhere.
            let sig = to_spend_auth(&sig).expect("the same bytes, the other type");
            assert!(
                n.rk.verify(&sighash, &sig).is_ok(),
                "the share set produced a bad signature"
            );

            payout
                .apply(n.index, sighash, sig)
                .expect("orchard must accept it");
        }
    }

    /// A signature under the wrong randomizer is refused by the action, not by
    /// the network. This is the check that makes `alpha` load-bearing.
    #[test]
    fn a_signature_under_the_wrong_randomizer_is_refused() {
        let keys: Vec<(Identifier, crate::ceremony::VaultKeys)> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .collect();
        let (store, fvk, change_to) = funded_vault(100_000, &keys);
        let mut payout = build(
            &store,
            &fvk,
            None,
            &[Payment::new(a_recipient(), 100)],
            change_to,
            v3(),
            rand::rngs::OsRng,
        )
        .unwrap();
        let sighash = [0x22u8; 32];
        let needed = payout.needs_signatures(keys[0].1.public_package.verifying_key());

        // Sign with a randomizer that is not this action's.
        let mut wrong_bytes = [0u8; 32];
        wrong_bytes[0] = 99;
        let wrong = Randomizer::deserialize(&wrong_bytes).unwrap();

        let sessions: Vec<SigningSession> = keys
            .iter()
            .take(2)
            .map(|(id, k)| SigningSession::begin(*id, k, &mut rand::rngs::OsRng))
            .collect();
        let mut coord = Coordinator::new(sighash.to_vec(), 2);
        for s in &sessions {
            coord.add_commitment(s.id(), s.commitments());
        }
        let package = coord.package().unwrap();
        let mut shares = BTreeMap::new();
        for (s, (_, k)) in sessions.into_iter().zip(keys.iter()) {
            let id = s.id();
            shares.insert(id, sign_share(s, k, &package, wrong).unwrap());
        }
        let params = params_for(keys[0].1.public_package.verifying_key(), wrong);
        let sig = aggregate(&package, &shares, &keys[0].1.public_package, &params).unwrap();

        assert!(
            matches!(
                payout.apply(needed[0].index, sighash, to_spend_auth(&sig).unwrap()),
                Err(PayoutError::BadSignature)
            ),
            "an action accepted a signature under another randomizer"
        );
    }

    #[test]
    fn a_vault_that_cannot_afford_it_refuses_to_build() {
        let keys: Vec<(Identifier, crate::ceremony::VaultKeys)> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .collect();
        let (store, fvk, change_to) = funded_vault(10, &keys);
        let out = build(
            &store,
            &fvk,
            None,
            &[Payment::new(a_recipient(), 1_000_000)],
            change_to,
            v3(),
            rand::rngs::OsRng,
        );
        assert!(matches!(
            out,
            Err(PayoutError::Notes(NoteError::Insufficient { .. }))
        ));
    }

    /// Change is an output, never a fee. The difference between what a payout
    /// spends and what it pays has to go somewhere the vault still owns.
    #[test]
    fn change_returns_to_the_vault() {
        let keys: Vec<(Identifier, crate::ceremony::VaultKeys)> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .collect();
        let (store, fvk, change_to) = funded_vault(100_000, &keys);
        let payout = build(
            &store,
            &fvk,
            None,
            &[Payment::new(a_recipient(), 400)],
            change_to,
            v3(),
            rand::rngs::OsRng,
        )
        .unwrap();
        // One spend of 100_000 paying 400: the rest, less the fee, is change
        // in its own action. Nothing becomes an accidental fee.
        assert_eq!(
            payout.bundle().actions().len(),
            2,
            "spend action and change action"
        );
        assert_eq!(payout.spent().len(), 1);
        assert_eq!(payout.spent()[0].value(), 100_000);
        assert_eq!(payout.fee, zip317_fee(2, 1));
    }

    /// The whole thing, proof included: a v5 transaction the network could
    /// take. Parsed back with the standard reader, its proof verified with the
    /// standard verifying key, and its sighash recomputed from the parsed
    /// bytes and found equal to the one the signers authorised.
    ///
    /// Slow (the proving key is built here), and the only test that shows the
    /// envelope is right — every cheaper one stops at the bundle.
    #[test]
    fn a_payout_becomes_a_valid_v5_transaction() {
        let keys: Vec<(Identifier, crate::ceremony::VaultKeys)> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .collect();
        let (store, fvk, change_to) = funded_vault(100_000, &keys);
        let mut payout = build(
            &store,
            &fvk,
            None,
            &[Payment::new(a_recipient(), 400)],
            change_to,
            v3(),
            rand::rngs::OsRng,
        )
        .unwrap();

        let env = Envelope::testnet_at(4_300_000);
        let sighash = payout.sighash(&env).unwrap();
        payout.finalize_io(sighash, rand::rngs::OsRng).unwrap();
        let pk = proving_key(env.bundle_version().unwrap());
        payout.prove(&pk, rand::rngs::OsRng).unwrap();

        let refs: Vec<(Identifier, &crate::ceremony::VaultKeys)> =
            keys.iter().map(|(i, k)| (*i, k)).collect();
        assert_eq!(
            sign_all(&mut payout, sighash, &refs, 2, rand::rngs::OsRng).unwrap(),
            2,
            "spend action and change action"
        );

        let sealed_fee = payout.fee;
        assert_eq!(
            sealed_fee,
            zip317_fee(2, 1),
            "one spend, one change, one t-out"
        );
        let sealed = payout.extract(sighash, &env, rand::rngs::OsRng).unwrap();
        assert_eq!(sealed.spent.len(), 1);
        assert_eq!(sealed.txid_hex().len(), 64);

        // The standard reader accepts it, and the proof verifies.
        let tx = zcash_primitives::transaction::Transaction::read(&sealed.bytes[..], env.branch)
            .expect("a well-formed v5 transaction");
        assert_eq!(*tx.txid().as_ref(), sealed.txid);
        let data = tx.into_data();
        let bundle = data.orchard_bundle().expect("an orchard bundle");
        assert_eq!(
            bundle.actions().len(),
            2,
            "one spend and one change, an action each"
        );
        bundle
            .verify_proof(&verifying_key(env.bundle_version().unwrap()))
            .expect("the proof verifies");
        // Value left the pool for the transparent output, plus the fee.
        assert_eq!(i64::from(*bundle.value_balance()), 400 + sealed_fee as i64);
        let t = data.transparent_bundle().expect("a transparent output");
        assert_eq!(t.vout.len(), 1);
        assert_eq!(u64::from(t.vout[0].value()), 400);
        assert!(
            data.ironwood_bundle().is_none(),
            "an Orchard payout is a v5 transaction"
        );

        // The sighash the signers authorised is the one the parsed transaction
        // yields: envelope and bundle agree.
        let effects = data.orchard_bundle().cloned().map(|b| {
            b.map_authorization(&mut (), |_, _, _| (), |_, _| orchard::bundle::EffectsOnly)
        });
        let mut tb = TransparentBuilder::empty();
        for o in &data.transparent_bundle().unwrap().vout {
            tb.add_output(&o.recipient_address().unwrap(), o.value())
                .unwrap();
        }
        let again_tx = TransactionData::<Effects>::from_parts(
            data.version(),
            data.consensus_branch_id(),
            data.lock_time(),
            data.expiry_height(),
            tb.build(),
            None,
            None,
            effects,
        );
        let digests = again_tx.digest(TxIdDigester);
        let again = signature_hash(&again_tx, &SignableInput::Shielded, &digests);
        assert_eq!(
            *again.as_ref(),
            sighash,
            "the sighash changed between signing and sealing"
        );
    }

    /// The Ironwood exit: a shielded recipient, paid directly, in a v6
    /// transaction with a real proof. The recipient decrypts the output with
    /// their own key — the payment is checked from the receiving side.
    #[test]
    fn an_ironwood_payout_pays_a_shielded_address_in_a_v6_transaction() {
        let keys: Vec<(Identifier, crate::ceremony::VaultKeys)> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .collect();
        let env = Envelope::testnet_at(4_326_900);
        let version = env.bundle_version_for(ValuePool::Ironwood).unwrap();
        assert!(
            version.default_flags().cross_address_enabled(),
            "Ironwood permits paying another address"
        );
        let (store, fvk, change_to) = funded_vault_v(100_000, &keys, version.note_version());

        let their_sk = SpendingKey::from_bytes([42u8; 32]).unwrap();
        let their_fvk = FullViewingKey::from(&their_sk);
        let them = their_fvk.address_at(0u32, Scope::External);
        let mut payout = build(
            &store,
            &fvk,
            Some(fvk.to_ovk(Scope::External)),
            &[Payment::new(Destination::Shielded(them), 40_000)],
            change_to,
            version,
            rand::rngs::OsRng,
        )
        .unwrap();
        assert_eq!(payout.pool, ValuePool::Ironwood);
        let sighash = payout.sighash(&env).unwrap();
        payout.finalize_io(sighash, rand::rngs::OsRng).unwrap();
        payout
            .prove(&proving_key(version), rand::rngs::OsRng)
            .unwrap();
        let refs: Vec<(Identifier, &crate::ceremony::VaultKeys)> =
            keys.iter().map(|(i, k)| (*i, k)).collect();
        sign_all(&mut payout, sighash, &refs, 2, rand::rngs::OsRng).unwrap();
        let fee = payout.fee;
        let sealed = payout.extract(sighash, &env, rand::rngs::OsRng).unwrap();

        let tx = zcash_primitives::transaction::Transaction::read(&sealed.bytes[..], env.branch)
            .expect("a v6 transaction");
        assert_eq!(tx.version(), TxVersion::V6);
        assert!(tx.orchard_bundle().is_none() && tx.transparent_bundle().is_none());
        let b = tx.ironwood_bundle().expect("an ironwood bundle");
        b.verify_proof(&verifying_key(version))
            .expect("the proof verifies");
        assert_eq!(
            i64::from(*b.value_balance()),
            fee as i64,
            "only the fee leaves the pool"
        );

        // The recipient finds their 40_000 zat.
        let ivk =
            orchard::keys::PreparedIncomingViewingKey::new(&their_fvk.to_ivk(Scope::External));
        let received: Vec<u64> = b
            .actions()
            .iter()
            .filter_map(|a| {
                zcash_note_encryption::try_note_decryption(
                    &orchard::note_encryption::IronwoodDomain::for_action(a),
                    &ivk,
                    a,
                )
            })
            .map(|(n, _, _)| n.value().inner())
            .collect();
        assert_eq!(received, vec![40_000]);
    }

    /// The bug the first real exit found: the vault's own change came back
    /// with no memo and the scanner stopped, calling it a deposit nobody
    /// claimed. A note to us in a transaction that spends our note is change.
    #[test]
    fn a_payouts_change_is_not_a_deposit() {
        let keys: Vec<(Identifier, crate::ceremony::VaultKeys)> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .collect();
        let env = Envelope::testnet_at(4_326_900);
        let version = env.bundle_version_for(ValuePool::Ironwood).unwrap();
        let (store, fvk, change_to) = funded_vault_v(100_000, &keys, version.note_version());
        let them = FullViewingKey::from(&SpendingKey::from_bytes([42u8; 32]).unwrap())
            .address_at(0u32, Scope::External);
        let mut payout = build(
            &store,
            &fvk,
            Some(fvk.to_ovk(Scope::External)),
            &[Payment::new(Destination::Shielded(them), 40_000)],
            change_to,
            version,
            rand::rngs::OsRng,
        )
        .unwrap();
        let sighash = payout.sighash(&env).unwrap();
        payout.finalize_io(sighash, rand::rngs::OsRng).unwrap();
        payout
            .prove(&proving_key(version), rand::rngs::OsRng)
            .unwrap();
        let refs: Vec<(Identifier, &crate::ceremony::VaultKeys)> =
            keys.iter().map(|(i, k)| (*i, k)).collect();
        sign_all(&mut payout, sighash, &refs, 2, rand::rngs::OsRng).unwrap();
        let sealed = payout.extract(sighash, &env, rand::rngs::OsRng).unwrap();

        // Scan our own transaction as the vault would.
        let vault = crate::shielded::VaultKeys::from_full_viewing_key(fvk.clone());
        let scanned = vault
            .scan_actions_lenient(&sealed.bytes, sealed.txid, 1)
            .unwrap();
        let change: Vec<u64> = scanned
            .actions
            .iter()
            .filter_map(|a| a.ours.as_ref())
            .map(|n| n.value().inner())
            .collect();
        assert_eq!(
            change,
            vec![100_000 - 40_000 - payout_fee(&sealed)],
            "the change note is ours and memo-less"
        );
        assert!(scanned.actions.iter().all(|a| a.account.is_none()));
        let spends_ours = scanned
            .actions
            .iter()
            .any(|a| store.holds_nullifier(&a.nullifier, &fvk));
        assert!(spends_ours, "the transaction spends the vault's note");

        // With the spend recognised: no deposit, no refusal.
        assert_eq!(
            crate::shielded::classify(&scanned, true, None, sealed.txid, 1).unwrap(),
            vec![]
        );
        // Without it, the same note would have stopped the scan — the bug.
        assert!(crate::shielded::classify(&scanned, false, None, sealed.txid, 1).is_err());
    }

    /// A wallet finds its note from the compact form alone — nullifier,
    /// commitment, ephemeral key, 52 bytes of ciphertext — in either pool.
    #[test]
    fn a_compact_block_is_enough_to_find_a_note() {
        let keys: Vec<(Identifier, crate::ceremony::VaultKeys)> = Ceremony::new(2, 3)
            .unwrap()
            .run(&mut rand::rngs::OsRng)
            .unwrap()
            .into_iter()
            .collect();
        let env = Envelope::testnet_at(4_326_900);
        let version = env.bundle_version_for(ValuePool::Ironwood).unwrap();
        let (store, fvk, change_to) = funded_vault_v(100_000, &keys, version.note_version());
        let their_fvk = FullViewingKey::from(&SpendingKey::from_bytes([42u8; 32]).unwrap());
        let them = their_fvk.address_at(0u32, Scope::External);
        let mut payout = build(
            &store,
            &fvk,
            Some(fvk.to_ovk(Scope::External)),
            &[Payment::new(Destination::Shielded(them), 40_000)],
            change_to,
            version,
            rand::rngs::OsRng,
        )
        .unwrap();
        let sighash = payout.sighash(&env).unwrap();
        payout.finalize_io(sighash, rand::rngs::OsRng).unwrap();
        payout
            .prove(&proving_key(version), rand::rngs::OsRng)
            .unwrap();
        let refs: Vec<(Identifier, &crate::ceremony::VaultKeys)> =
            keys.iter().map(|(i, k)| (*i, k)).collect();
        sign_all(&mut payout, sighash, &refs, 2, rand::rngs::OsRng).unwrap();
        let sealed = payout.extract(sighash, &env, rand::rngs::OsRng).unwrap();
        let tx = zcash_primitives::transaction::Transaction::read(&sealed.bytes[..], env.branch)
            .unwrap();

        let ctx = crate::compact::CompactTx::from_transaction(3, &tx);
        let block = crate::compact::CompactBlock {
            height: 9,
            hash: [0u8; 32],
            txs: vec![ctx],
        };
        let back = crate::compact::CompactBlock::decode(&block.encode()).unwrap();
        assert_eq!(back, block, "the compact form round-trips");

        let ivk =
            orchard::keys::PreparedIncomingViewingKey::new(&their_fvk.to_ivk(Scope::External));
        let hits = crate::compact::scan(&back, &ivk);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            (hits[0].pool, hits[0].value, hits[0].tx_index),
            (ValuePool::Ironwood, 40_000, 3)
        );
        // The vault's own key finds only the change: what it held, less the
        // payment and the fee this bundle paid.
        let vault_ivk =
            orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
        let mine = crate::compact::scan(&back, &vault_ivk);
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].value, 100_000 - 40_000 - payout_fee(&sealed));
        // A stranger finds nothing.
        let nobody = orchard::keys::PreparedIncomingViewingKey::new(
            &FullViewingKey::from(&SpendingKey::from_bytes([77u8; 32]).unwrap())
                .to_ivk(Scope::External),
        );
        assert!(crate::compact::scan(&back, &nobody).is_empty());
    }

    fn payout_fee(_s: &Sealed) -> u64 {
        zip317_fee(2, 0)
    }

    #[test]
    fn a_transparent_address_parses_with_its_checksum() {
        let good = "tmAMWUnnjjpM7TDb81PykSxGJpThsw453ND";
        assert_eq!(
            transparent_address(good, Network::TestNetwork),
            Some(TransparentAddress::PublicKeyHash([7u8; 20]))
        );
        assert_eq!(
            transparent_address(good, Network::MainNetwork),
            None,
            "a testnet prefix on mainnet"
        );
        let mut bad = good.to_string();
        bad.replace_range(5..6, if &good[5..6] == "1" { "2" } else { "1" });
        assert_eq!(
            transparent_address(&bad, Network::TestNetwork),
            None,
            "a corrupted address passed"
        );
        assert_eq!(
            transparent_address("utest1notatransparentaddress", Network::TestNetwork),
            None
        );
    }
}
