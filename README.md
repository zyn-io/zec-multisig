# zec-multisig

Threshold custody for shielded Zcash funds: a vault whose spending key exists
only as a threshold of shares held on separate machines. No single box can
spend, the coordinator holds no share, and losing one custodian loses nothing.

```
11,582 lines of Rust    130 tests    no unsafe
```

## What this is not

**No cryptography is implemented here.** Threshold signing fails silently and
totally when it is got wrong, so this crate integrates the Zcash Foundation's
audited [`reddsa`](https://crates.io/crates/reddsa) FROST over RedPallas — the
scheme Orchard spend authorisation already uses — and reimplements no part of
it.

## What this is

`frost-rerandomized` hands you a *signature*. It does not hand you a *Zcash
transaction*. Everything in between is this crate:

| | |
|---|---|
| `ceremony`, `dkg_net` | Distributed key generation over an encrypted transport (x25519 + ChaCha20-Poly1305). No dealer ever holds the whole key. |
| `custodian`, `custody_net` | The share-holder daemon and the protocol it speaks. Everything crossing the wire is public — sighash, randomizers, nonce commitments, signature shares. The share never crosses. |
| `signing` | The two FROST rounds, and aggregation. |
| `notes`, `shielded`, `payout` | Note selection, witness tracking, and assembly of the Orchard spend the signature authorises. |
| `zebra`, `lightd`, `compact` | How it sees the chain. |
| `watcher` | Confirmed deposits into credits: confirmation depth, reorgs, deduplication, ordering. The logic that is easy to get wrong and has nothing to do with cryptography. |

Two ciphersuites are carried throughout: **RedPallas**, which is what Orchard
spend authorisation uses, and plain **Ed25519** for a second vault where one
is wanted. Same protocol, different curve; a daemon may hold a share of
either, or both, and an op for a share it does not hold is refused rather
than half-answered.

## Status

Extracted from a system that has run 2-of-3 threshold custody with the
coordinator holding no share. Published so the operational half of shielded
threshold custody is not something every project has to rediscover.

This has not been independently audited. The cryptography it depends on has
been (NCC Group, Least Authority, on `frost-core`); the assembly around it
has not.

## Compatibility constants

Three identifiers are **wire and storage formats**, not names. Changing any of
them makes an existing deployment unreadable:

- `memo::MEMO_TAG` (`b"ZEC"`) — the on-chain memo prefix a deposit carries,
  and `ZEC1:<hex>` in its typed text form
- `account::ACCOUNT_DOMAIN` (`b"zec.account.v1"`) — defines an account space;
  two deployments that disagree derive different accounts from the same key
- `ZECCB1` / `ZECNOTE1` — on-disk magics for the compact-block and note stores

Pick your own values before a first deployment. Never change one after.

## License

MIT OR Apache-2.0, at your option.
