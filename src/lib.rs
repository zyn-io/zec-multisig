//! Threshold custody for shielded Zcash funds.
//!
//! A vault whose spending key exists only as a threshold of shares held on
//! separate machines. No single box can spend, the coordinator holds no
//! share, and losing one custodian loses nothing.
//!
//! **No cryptography is implemented here.** Threshold signing fails silently
//! and totally when it is got wrong, so this crate integrates `reddsa`'s
//! FROST over RedPallas — the Zcash Foundation's implementation of the scheme
//! Orchard spend authorisation already uses — and reimplements no part of it.
//!
//! What it supplies is the distance between a signature and a transaction:
//!
//! - [`ceremony`] and [`dkg_net`] generate the key as shares, over an
//!   encrypted transport, with no dealer ever holding the whole.
//! - [`custodian`] and [`custody_net`] are the share-holder daemon and the
//!   protocol it speaks. Everything that crosses the wire is public; the
//!   share never does.
//! - [`signing`] runs the two rounds and aggregates.
//! - [`notes`], [`shielded`] and [`payout`] select notes, track witnesses and
//!   assemble the Orchard spend the signature authorises.
//! - [`zebra`], [`lightd`] and [`compact`] are how it sees the chain.
//! - [`watcher`] turns confirmed deposits into credits: confirmation depth,
//!   reorgs, deduplication and ordering — the logic that is easy to get wrong
//!   and has nothing to do with cryptography.
//!
//! Two ciphersuites are carried throughout: RedPallas for Zcash, and Ed25519
//! for a second vault where one is wanted. They are the same protocol over a
//! different curve, and a daemon may hold a share of either or both.

// The FROST core, so a binary can name a ciphersuite bound without taking its
// own dependency on the exact version this crate was built against.
pub use frost_core;

pub mod account;
pub mod amount;
pub mod base58;
pub mod ceremony;
pub mod compact;
pub mod custodian;
pub mod custody_net;
pub mod dkg_net;
pub mod ed25519;
pub mod lightd;
pub mod memo;
pub mod notes;
pub mod payout;
pub mod shares;
pub mod shielded;
pub mod signing;
pub mod transparent;
pub mod watcher;
pub mod zebra;

pub use account::AccountId;
pub use ceremony::{Ceremony, CeremonyError, VaultKeys};
pub use memo::{MemoError, MEMO_TAG, MEMO_VERSION};
pub use signing::{SigningError, SigningSession};
pub use watcher::{ChainView, ObservedDeposit, Watcher, WatcherAction, WatcherError};
