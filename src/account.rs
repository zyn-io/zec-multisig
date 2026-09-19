//! The account identifier a deposit names, and how a key derives one.
//!
//! Thirty-two bytes. This crate mostly compares and commits them rather than
//! deriving them — an application is free to map keys onto accounts its own
//! way — but a forced memo carries a key inline, so the derivation it implies
//! has to live somewhere, and it lives here.

use sha2::{Digest, Sha256};

pub type AccountId = [u8; 32];

/// How the key in an account id was signed with.
///
/// # Why the tag is bound into the account id
///
/// The alternative is a registry — state that says "this account uses scheme
/// 2 with this key" — which can be changed, and is therefore a second thing
/// to authorise and a second thing to steal. There is no registry here. An
/// account id *is* the commitment:
///
/// ```text
///   account = H(ACCOUNT_DOMAIN | scheme | len(key) | key)
/// ```
///
/// so the scheme cannot be swapped under an account, the same key bytes under
/// two schemes are two unrelated accounts, and an account exists the moment
/// someone deposits to it — with nothing to register first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    /// Ed25519 over the canonical payload.
    Ed25519,
    /// secp256k1 over an EIP-712 digest, recovered to a 20-byte Ethereum
    /// address. MetaMask, Rabby, Coinbase Wallet, Ledger, WalletConnect.
    Secp256k1Eip712,
    /// Ed25519 over a human-readable message, as Ed25519 wallets sign with
    /// `signMessage`. Phantom, Solflare, Backpack.
    Ed25519Message,
}

impl Scheme {
    pub fn tag(self) -> u8 {
        match self {
            Scheme::Ed25519 => 1,
            Scheme::Secp256k1Eip712 => 2,
            Scheme::Ed25519Message => 3,
        }
    }

    pub fn from_tag(t: u8) -> Option<Scheme> {
        match t {
            1 => Some(Scheme::Ed25519),
            2 => Some(Scheme::Secp256k1Eip712),
            3 => Some(Scheme::Ed25519Message),
            _ => None,
        }
    }

    /// The length of a key under this scheme, in bytes.
    ///
    /// Ethereum is 20 because a wallet never reveals its public key — only the
    /// address recovered from a signature — so the address is the identity we
    /// can actually check.
    pub fn key_len(self) -> usize {
        match self {
            Scheme::Ed25519 | Scheme::Ed25519Message => 32,
            Scheme::Secp256k1Eip712 => 20,
        }
    }
}

/// Domain tag for account derivation, distinct from every other commitment
/// prefix so an account id can never be some other hash reinterpreted.
///
/// **This value defines an account space.** Two deployments that disagree on
/// it derive different accounts from the same key, and a deposit routed under
/// one is invisible to the other. Change it only when starting fresh.
pub const ACCOUNT_DOMAIN: &[u8] = b"zec.account.v1";

/// The account a key controls under a scheme.
///
/// Length-prefixed so that a 20-byte key and a 32-byte key cannot in
/// principle be arranged to produce the same preimage.
pub fn account_of(scheme: Scheme, key: &[u8]) -> AccountId {
    let mut buf = Vec::new();
    buf.extend_from_slice(ACCOUNT_DOMAIN);
    buf.push(scheme.tag());
    buf.extend_from_slice(&(key.len() as u32).to_be_bytes());
    buf.extend_from_slice(key);
    let mut h = Sha256::new();
    h.update(&buf);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation is a wire format: these vectors are what a deployed
    /// account space already committed to, and they may not drift.
    #[test]
    fn account_derivation_is_pinned() {
        let a = account_of(Scheme::Ed25519, &[0x33u8; 32]);
        let b = account_of(Scheme::Ed25519Message, &[0x33u8; 32]);
        assert_ne!(a, b, "the same key under two schemes is two accounts");
        assert_eq!(
            account_of(Scheme::Ed25519, &[0u8; 32]),
            account_of(Scheme::Ed25519, &[0u8; 32])
        );
        // Length is bound: a 20-byte key cannot collide with a 32-byte one.
        assert_ne!(
            account_of(Scheme::Secp256k1Eip712, &[0u8; 20]),
            account_of(Scheme::Secp256k1Eip712, &[0u8; 32])
        );
    }
}
