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

Extracted from a system running 2-of-3 threshold custody with the coordinator
holding no share. Published so the operational half of shielded threshold
custody is not something every project has to rediscover.

**A signature this code produced authorised a shielded spend on Zcash mainnet
on 21 September 2026** — transaction
[`e4e66e727475429093147e60f5924fd1111ac4276aa9dee3dea844cd0eda87e6`](https://blockchair.com/zcash/transaction/e4e66e727475429093147e60f5924fd1111ac4276aa9dee3dea844cd0eda87e6),
an Ironwood bundle whose spend authorisation was aggregated from two of three
shares held on separate machines. The third custodian was unreachable at the
time and the quorum formed without it, which is the property the whole design
exists for.

This has not been independently audited. The cryptography it depends on has
been (NCC Group, Least Authority, on `frost-core`); the assembly around it
has not.

## Compatibility constants

These are **wire, storage and domain-separation constants**, not names.
Changing any of them makes an existing deployment unreadable, or silently
derives different values from the same inputs:

| constant | value | what it fixes |
|---|---|---|
| `memo::MEMO_TAG` | `b"ZEC"` | deposit memo prefix (`ZEC1:<hex>` in typed text form) |
| `memo::ANCHOR_TAG` | `b"ZEA"` | the vault's self-send carrying a state root |
| `memo::PUBLISH_TAG` | `b"ZEP"` | a published digest |
| `memo::FORCED_TAG` | `b"ZEF"` | a forced instruction frame |
| `memo::APP_PAYMENT_TAG` | `b"ZEB"` | a purpose-bound application payment |
| `account::ACCOUNT_DOMAIN` | `zec.account.v1` | defines an account space |
| deposit index domain | `zec.deposit.index.v1` | deposit ordering within a block |
| DKG seal domain | `zec.dkg.seal.v1` | key derivation for the ceremony transport |

Pick your own values before a first deployment. Never change one after.

## Application payments

`ZEB` is a reserved namespace for payments an application must account for
separately from ordinary deposits — an invoice, a subscription, a sale. The
crate fixes the frame (version, purpose byte, 32-byte reference, recipient)
and leaves the meaning open: **the purpose byte is yours to define**, any
non-zero value is carried through untouched, and your application refuses the
codes it does not recognise.

The point is that the two paths can never be confused. A note carrying a `ZEB`
memo is surfaced as an application payment and is never also credited as a
deposit, and a *malformed* `ZEB` memo fails closed rather than falling through
into the deposit path.

## License

MIT OR Apache-2.0, at your option.
