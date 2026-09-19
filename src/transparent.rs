//! The doormat: transparent receiving, so money can get *in*.
//!
//! Zyn is shielded everywhere it matters, and the vault refuses transparent
//! custody outright (`zebra.rs`, and DECISIONS §38.4). None of that helps a
//! person holding ZEC on an exchange, because **every exchange pays out to a
//! transparent address**. A wallet that cannot receive one cannot be funded
//! without a second wallet in between, and "install another wallet first" is
//! where most people stop.
//!
//! So a transparent receiver exists here, and exactly one rule governs it:
//! **transparent is a doormat, not a room.** Funds are received there and
//! shielded immediately. Nothing rests transparent, nothing is spent from
//! transparent to anywhere but the holder's own shielded address. The privacy
//! given up is the association between a t-address and this wallet — and that
//! address is public on-chain the moment the exchange pays it either way.
//!
//! Derivation is BIP-32/44 at `m/44'/133'/account'/0/index`, the path every
//! other Zcash wallet uses, so a holder can always sweep these funds with
//! something else. That interoperability is the whole reason not to invent a
//! bespoke derivation from the same seed.

use zcash_protocol::consensus::{NetworkType, Parameters};
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex};

/// One transparent receiving key and the address it answers to.
pub struct Receiver {
    secret: secp256k1::SecretKey,
    address: TransparentAddress,
}

impl Receiver {
    /// Derive from a wallet seed at `m/44'/133'/account'/0/index`.
    ///
    /// The seed is the wallet's own 32 bytes. They are not a BIP-39 mnemonic
    /// seed — this wallet has never had one — but they are 32 bytes of
    /// entropy, which is what the derivation wants.
    pub fn derive<P: Parameters>(
        params: &P,
        seed: &[u8],
        account: u32,
        index: u32,
    ) -> Option<Receiver> {
        let account_key =
            AccountPrivKey::from_seed(params, seed, zip32::AccountId::try_from(account).ok()?)
                .ok()?;
        let child = NonHardenedChildIndex::from_index(index)?;
        let secret = account_key.derive_external_secret_key(child).ok()?;
        let address = account_key
            .to_account_pubkey()
            .derive_external_ivk()
            .ok()?
            .derive_address(child)
            .ok()?;
        Some(Receiver { secret, address })
    }

    pub fn address(&self) -> &TransparentAddress {
        &self.address
    }

    pub fn secret(&self) -> &secp256k1::SecretKey {
        &self.secret
    }

    /// The address as a wallet or an exchange will accept it.
    pub fn encoded(&self, network: NetworkType) -> String {
        encode_transparent(&self.address, network)
    }
}

/// Base58Check, the inverse of `payout::transparent_address`.
///
/// Kept beside the parser it mirrors would be neater, but the parser lives in
/// the payout path and this is the receive path; what matters is that the two
/// prefix tables are identical, which the round-trip test below enforces.
pub fn encode_transparent(addr: &TransparentAddress, network: NetworkType) -> String {
    let (p2pkh, p2sh): ([u8; 2], [u8; 2]) = match network {
        NetworkType::Main => ([0x1C, 0xB8], [0x1C, 0xBD]),
        _ => ([0x1D, 0x25], [0x1C, 0xBA]),
    };
    let (prefix, hash) = match addr {
        TransparentAddress::PublicKeyHash(h) => (p2pkh, h),
        TransparentAddress::ScriptHash(h) => (p2sh, h),
    };
    let mut body = Vec::with_capacity(22);
    body.extend_from_slice(&prefix);
    body.extend_from_slice(hash);
    use sha2::Digest;
    let check = sha2::Sha256::digest(sha2::Sha256::digest(&body));
    let mut full = body;
    full.extend_from_slice(&check[..4]);
    crate::base58::base58_encode(&full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};

    /// Derivation is deterministic: the same seed gives the same address every
    /// time, on every machine. A wallet whose receiving address moved would
    /// lose whatever was sent to the old one.
    #[test]
    fn the_same_seed_always_derives_the_same_address() {
        let seed = [7u8; 32];
        let a = Receiver::derive(&MAIN_NETWORK, &seed, 0, 0).expect("derive");
        let b = Receiver::derive(&MAIN_NETWORK, &seed, 0, 0).expect("derive");
        assert_eq!(a.encoded(NetworkType::Main), b.encoded(NetworkType::Main));
    }

    /// A different seed is a different wallet.
    #[test]
    fn a_different_seed_derives_a_different_address() {
        let a = Receiver::derive(&MAIN_NETWORK, &[7u8; 32], 0, 0).expect("derive");
        let b = Receiver::derive(&MAIN_NETWORK, &[8u8; 32], 0, 0).expect("derive");
        assert_ne!(a.encoded(NetworkType::Main), b.encoded(NetworkType::Main));
    }

    /// Mainnet and testnet addresses are not interchangeable, and the prefix
    /// is what an exchange checks before it will pay one.
    #[test]
    fn mainnet_and_testnet_addresses_differ_and_carry_the_right_prefix() {
        let seed = [3u8; 32];
        let m = Receiver::derive(&MAIN_NETWORK, &seed, 0, 0)
            .expect("derive")
            .encoded(NetworkType::Main);
        let t = Receiver::derive(&TEST_NETWORK, &seed, 0, 0)
            .expect("derive")
            .encoded(NetworkType::Test);
        assert!(m.starts_with("t1"), "mainnet p2pkh starts t1, got {}", m);
        assert!(t.starts_with("tm"), "testnet p2pkh starts tm, got {}", t);
        assert_ne!(m, t);
    }

    /// The encoder and the payout path's parser must agree, or the wallet
    /// would hand out an address it cannot itself recognise.
    #[test]
    fn an_encoded_address_parses_back_to_the_same_hash() {
        // `MAIN_NETWORK` and `TEST_NETWORK` are distinct types, so the two
        // cases cannot share a loop.
        let m = Receiver::derive(&MAIN_NETWORK, &[11u8; 32], 0, 0).expect("derive");
        let s = m.encoded(NetworkType::Main);
        let back =
            crate::payout::transparent_address(&s, zcash_protocol::consensus::Network::MainNetwork)
                .expect("the parser must accept what the encoder produced");
        assert_eq!(&back, m.address(), "round trip changed the mainnet address");

        let t = Receiver::derive(&TEST_NETWORK, &[11u8; 32], 0, 0).expect("derive");
        let s = t.encoded(NetworkType::Test);
        let back =
            crate::payout::transparent_address(&s, zcash_protocol::consensus::Network::TestNetwork)
                .expect("the parser must accept what the encoder produced");
        assert_eq!(&back, t.address(), "round trip changed the testnet address");
    }

    /// Successive indices are distinct addresses — the basis of not reusing
    /// one, which is the only privacy hygiene available on a public pool.
    #[test]
    fn successive_indices_give_distinct_addresses() {
        let seed = [5u8; 32];
        let a = Receiver::derive(&MAIN_NETWORK, &seed, 0, 0)
            .expect("derive")
            .encoded(NetworkType::Main);
        let b = Receiver::derive(&MAIN_NETWORK, &seed, 0, 1)
            .expect("derive")
            .encoded(NetworkType::Main);
        assert_ne!(a, b);
    }
}

// ---- sweeping the doormat ----

use crate::lightd::Utxo;
use crate::payout::{Effects, Envelope, PayoutError, Sealed};
use orchard::builder::{Builder, BundleType};
use orchard::bundle::BundleVersion;
use orchard::keys::{FullViewingKey, OutgoingViewingKey};
use orchard::value::NoteValue;
use orchard::Anchor;
use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{TransactionData, TxVersion};
use zcash_protocol::value::{ZatBalance, Zatoshis};
use zcash_transparent::builder::TransparentBuilder;
use zcash_transparent::bundle::{OutPoint, TxOut};
use zcash_transparent::sighash::SignableInput as TSignableInput;

/// Everything the doormat holds, and what it would cost to sweep it.
pub struct Sweep {
    pub total: u64,
    pub fee: u64,
    /// What lands shielded. Zero means the fee eats it — see [`shield`].
    pub net: u64,
    pub count: usize,
}

/// What sweeping these outputs would yield, before building anything.
///
/// A caller shows this to the holder first: sweeping dust costs more in fees
/// than it moves, and a wallet that silently spends someone's money to move
/// nothing is worse than one that refuses.
pub fn plan(utxos: &[Utxo]) -> Sweep {
    let total: u64 = utxos.iter().map(|u| u.value).sum();
    // ZIP-317 counts logical actions per pool and charges the marginal fee for
    // each. Transparent contributes `max(inputs, outputs)` = one per output
    // being swept. The shielded side contributes the bundle's *actions*, and
    // `BundleType::DEFAULT` pads to two even for a single output — counting
    // the one output instead of the two actions underpays, and the node
    // rejects it as "unpaid actions is higher than the limit".
    const MARGINAL_FEE: u64 = 5_000;
    const PADDED_ORCHARD_ACTIONS: usize = 2;
    let fee = MARGINAL_FEE * (utxos.len().max(1) + PADDED_ORCHARD_ACTIONS).max(2) as u64;
    Sweep {
        total,
        fee,
        net: total.saturating_sub(fee),
        count: utxos.len(),
    }
}

/// Sweep transparent outputs into one shielded note the holder owns.
///
/// The doormat's only exit: everything in, one Orchard output out, to an
/// address derived from the same seed. There is deliberately no way to spend
/// transparent funds *anywhere else* — a transparent balance is a state to
/// leave, not one to transact from, and offering the choice would invite
/// exactly the public spending this whole system exists to avoid.
#[allow(clippy::too_many_arguments)]
pub fn shield(
    receivers: &[&Receiver],
    utxos: &[Utxo],
    to: orchard::Address,
    fvk: &FullViewingKey,
    ask: &orchard::keys::SpendAuthorizingKey,
    ovk: Option<OutgoingViewingKey>,
    version: BundleVersion,
    env: &Envelope,
    mut rng: impl rand::RngCore + rand::CryptoRng,
) -> Result<Sealed, PayoutError> {
    if utxos.is_empty() {
        return Err(PayoutError::Build("nothing to shield".into()));
    }
    let sweep = plan(utxos);
    if sweep.net == 0 {
        return Err(PayoutError::Build(format!(
            "{} zat across {} output(s) does not cover the {} zat fee",
            sweep.total, sweep.count, sweep.fee
        )));
    }

    // The shielded side: one output, no spends. An anchor is still required —
    // any valid one will do when nothing is being spent against it.
    let mut builder = Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        Anchor::empty_tree(),
    )
    .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;
    // A *change* output, not a payment: the money is already the holder's and
    // is returning to them. That is also the only shielded output NU6.3 lets
    // an Orchard bundle make, so calling it what it is happens to be the only
    // thing that works.
    builder
        .add_change_output(
            fvk.clone(),
            ovk.clone(),
            to,
            NoteValue::from_raw(sweep.net),
            [0u8; 512],
        )
        .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;
    let (mut bundle, _meta) = builder
        .build_for_pczt(&mut rng)
        .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;

    // The transparent side: every output, as a P2PKH input.
    let mut signing = zcash_transparent::builder::TransparentSigningSet::new();
    let mut t = TransparentBuilder::empty();
    for u in utxos {
        let r = receivers
            .iter()
            .find(|r| script_pays(&u.script, r.address()))
            .ok_or_else(|| {
                PayoutError::Build("an output pays an address this wallet cannot spend".into())
            })?;
        let pubkey = signing.add_key(*r.secret());
        let outpoint = OutPoint::new(u.txid, u.index);
        let value =
            Zatoshis::from_u64(u.value).map_err(|_| PayoutError::Build("utxo value".into()))?;
        // `Script::read` expects the wire form — a CompactSize length then the
        // bytes — while the node reports the script itself. A P2PKH script is
        // 25 bytes, comfortably inside the single-byte length encoding.
        if u.script.len() > 252 {
            return Err(PayoutError::Build(
                "scriptPubKey is longer than a P2PKH".into(),
            ));
        }
        let mut wire = Vec::with_capacity(u.script.len() + 1);
        wire.push(u.script.len() as u8);
        wire.extend_from_slice(&u.script);
        let script_pubkey = zcash_transparent::address::Script::read(&mut &wire[..])
            .map_err(|e| PayoutError::Build(format!("unreadable scriptPubKey: {}", e)))?;
        let coin = TxOut::new(value, script_pubkey);
        t.add_p2pkh_input(pubkey, outpoint, coin)
            .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;
    }
    let unauthorized = t
        .build()
        .ok_or_else(|| PayoutError::Build("no transparent bundle".into()))?;

    // One digest set serves both signatures: the shielded binding signature
    // and every transparent input's. They must be over the same transaction
    // or neither verifies.
    let effects = bundle
        .extract_effects::<ZatBalance>()
        .map_err(|e| PayoutError::Envelope(format!("{:?}", e)))?;
    // Ironwood exists only in v6 transactions; Orchard rides in v5. Getting
    // this wrong is not a rejection but a panic inside the builder, because
    // the flags cannot be represented at all.
    let pool = version.value_pool();
    let for_sighash = match pool {
        orchard::ValuePool::Orchard => TransactionData::<Effects>::from_parts(
            TxVersion::V5,
            env.branch,
            0,
            env.expiry,
            Some(unauthorized.clone()),
            None,
            None,
            effects,
        ),
        orchard::ValuePool::Ironwood => TransactionData::<Effects>::from_parts_v6(
            env.branch,
            0,
            env.expiry,
            Some(unauthorized.clone()),
            None,
            None,
            effects,
        ),
    };
    let digests = for_sighash.digest(TxIdDigester);
    let shielded_sighash: [u8; 32] =
        *signature_hash(&for_sighash, &SignableInput::Shielded, &digests).as_ref();

    // `BundleType::DEFAULT` pads the bundle with dummy spends, and a dummy is
    // still an action that must balance, prove and be signed. Skipping any of
    // the three fails only at the very end, as `MissingSpendAuthSig`.
    bundle
        .finalize_io(shielded_sighash, &mut rng)
        .map_err(|e| PayoutError::Envelope(format!("{:?}", e)))?;
    bundle
        .create_proof(&crate::payout::proving_key(version), &mut rng)
        .map_err(|e| PayoutError::Envelope(format!("{:?}", e)))?;
    // `finalize_io` has already signed the dummies. A sweep has no *real*
    // spends, so signing zero actions here is the expected outcome, not a
    // failure — the vault's payout path signs a spend per note and would
    // rightly complain at zero.
    for action in bundle.actions_mut() {
        let _ = action.sign(shielded_sighash, ask, &mut rng);
    }

    let authorized_t = unauthorized
        .apply_signatures(
            |input: TSignableInput| {
                *signature_hash(&for_sighash, &SignableInput::Transparent(input), &digests).as_ref()
            },
            &signing,
        )
        .map_err(|e| PayoutError::Build(format!("{:?}", e)))?;

    let authorized = bundle
        .extract::<ZatBalance>()
        .map_err(|e| PayoutError::Envelope(format!("{:?}", e)))?
        .ok_or_else(|| PayoutError::Envelope("no actions".into()))?
        .apply_binding_signature(shielded_sighash, &mut rng)
        .ok_or(PayoutError::BadSignature)?;

    let tx = match pool {
        orchard::ValuePool::Orchard => {
            TransactionData::<zcash_primitives::transaction::Authorized>::from_parts(
                TxVersion::V5,
                env.branch,
                0,
                env.expiry,
                Some(authorized_t),
                None,
                None,
                Some(authorized),
            )
        }
        orchard::ValuePool::Ironwood => {
            TransactionData::<zcash_primitives::transaction::Authorized>::from_parts_v6(
                env.branch,
                0,
                env.expiry,
                Some(authorized_t),
                None,
                None,
                Some(authorized),
            )
        }
    }
    .freeze()
    .map_err(|e| PayoutError::Envelope(e.to_string()))?;
    let mut bytes = Vec::new();
    tx.write(&mut bytes)
        .map_err(|e| PayoutError::Envelope(e.to_string()))?;
    Ok(Sealed {
        txid: *tx.txid().as_ref(),
        bytes,
        spent: Vec::new(),
    })
}

/// Whether a `scriptPubKey` is the standard P2PKH paying `addr`.
///
/// Checked rather than assumed: signing an input whose script we misread
/// produces a transaction the network rejects, and the money looks lost until
/// someone works out why.
fn script_pays(script: &[u8], addr: &TransparentAddress) -> bool {
    let TransparentAddress::PublicKeyHash(hash) = addr else {
        return false;
    };
    // OP_DUP OP_HASH160 <20> …20… OP_EQUALVERIFY OP_CHECKSIG
    script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && &script[3..23] == hash
        && script[23] == 0x88
        && script[24] == 0xac
}

#[cfg(test)]
mod sweep_tests {
    use super::*;
    use zcash_protocol::consensus::MAIN_NETWORK;

    fn p2pkh_script(addr: &TransparentAddress) -> Vec<u8> {
        let TransparentAddress::PublicKeyHash(h) = addr else {
            panic!("not p2pkh")
        };
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(h);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    /// The script check must accept the wallet's own address and nothing else.
    /// Signing an input we misread produces a transaction the network throws
    /// away, which looks to the holder exactly like losing the money.
    #[test]
    fn a_script_is_matched_to_the_address_that_can_spend_it() {
        let mine = Receiver::derive(&MAIN_NETWORK, &[1u8; 32], 0, 0).expect("derive");
        let theirs = Receiver::derive(&MAIN_NETWORK, &[2u8; 32], 0, 0).expect("derive");
        let script = p2pkh_script(mine.address());
        assert!(script_pays(&script, mine.address()));
        assert!(
            !script_pays(&script, theirs.address()),
            "another key must not match"
        );
        assert!(
            !script_pays(&script[..24], mine.address()),
            "a truncated script is not a match"
        );
        assert!(
            !script_pays(&[0u8; 25], mine.address()),
            "zeroes are not a script"
        );
    }

    /// Dust must be refused rather than swept: the fee would exceed it, and a
    /// wallet that spends someone's money to move nothing is worse than one
    /// that says no.
    #[test]
    fn a_sweep_that_the_fee_would_eat_is_refused() {
        let dust = Utxo {
            txid: [1u8; 32],
            index: 0,
            value: 1_000,
            height: 5,
            script: vec![],
        };
        let s = plan(&[dust]);
        assert_eq!(s.total, 1_000);
        assert!(s.fee > s.total, "the fee should exceed dust");
        assert_eq!(s.net, 0, "nothing would land");
    }

    /// A real balance nets out to the total less the fee, and the fee grows
    /// with the number of outputs being swept.
    #[test]
    fn a_plan_reports_what_would_actually_land() {
        let one = Utxo {
            txid: [1u8; 32],
            index: 0,
            value: 1_000_000,
            height: 5,
            script: vec![],
        };
        let mut two = one.clone();
        two.index = 1;
        let a = plan(std::slice::from_ref(&one));
        assert_eq!(a.net, 1_000_000 - a.fee);
        let b = plan(&[one, two]);
        assert!(b.fee > a.fee, "two inputs cost more than one");
        assert_eq!(b.total, 2_000_000);
    }
}
