//! How a Zcash deposit says which Zyn account it is for.
//!
//! A shielded deposit carries a 512-byte memo, readable only by a holder of the
//! vault's viewing key. That is where the recipient's Zyn account goes. It is
//! not a public leak — the memo is inside the encrypted note, so who can read it
//! is exactly the question of who holds the viewing key, and nothing more.
//!
//! # Why this is strict
//!
//! A memo is user-supplied text. Someone will send an empty one, a wallet's
//! default, a note to themselves, or thirty-two bytes of something else
//! entirely. Every one of those has to be *unmistakable* for a deposit
//! instruction, because the failure is crediting a stranger.
//!
//! So the format is tagged, versioned, fixed-length, and checked to the byte —
//! and anything that is not exactly right is not a deposit with a problem, it
//! is [`MemoError`] and a manual refund. Guessing is the one thing that must
//! not happen here.
//!
//! ```text
//!   "ZEC"  version:u8  account:[u8; 32]      36 bytes, then zero padding
//! ```
//!
//! # The alternative, and why not
//!
//! Zcash addresses support diversifiers, so each account could have its own
//! deposit address and need no memo at all — which removes the commonest way
//! people lose funds on exchanges, forgetting one. It also means the watcher
//! must keep a diversifier-to-account map, and a lost map is lost deposits.
//! Worth revisiting with a per-deposit diversifier and a scan window; the memo
//! is the version that is simple enough to be obviously right.

use crate::account::AccountId;

/// Marks a memo as a Zyn deposit instruction.
pub const MEMO_TAG: &[u8; 3] = b"ZEC";
/// Format version. A memo of another version is refused, not interpreted.
pub const MEMO_VERSION: u8 = 1;
/// Tag, version, account.
pub const MEMO_LEN: usize = 3 + 1 + 32;
/// A Zcash memo field.
pub const MEMO_FIELD: usize = 512;

/// The tag of an **anchor** memo — the vault's own self-send carrying a Zyn
/// state root (`zyn::anchor::MEMO_MAGIC`, kept equal by a test in `zynzapd`).
/// Distinct from [`MEMO_TAG`] in its first bytes so neither parser can accept
/// the other's payload.
pub const ANCHOR_TAG: &[u8; 3] = b"ZYA";
/// tag + version + chain id + epoch + anchor id.
pub const ANCHOR_LEN: usize = 3 + 1 + 4 + 8 + 32;

/// A **publication**: the vault stamping a 32-byte digest onto Zcash so that
/// what it commits to can be shown to have existed by a block height.
///
/// It exists because a commitment the operator could backdate is not a
/// commitment. A sale's close announcement names a height in the future; that
/// only means anything if the announcement itself provably predates it, and
/// nothing inside the announcement can establish its own age. A Zcash block
/// can (§100.6).
///
/// Deliberately the same shape as an anchor — tag, version, digest, zero
/// padding — so the scanner already treats it the way it treats an anchor:
/// recorded, never credited. It is money only in the sense that a postmark is.
pub const PUBLISH_TAG: &[u8; 3] = b"ZYP";
pub const PUBLISH_LEN: usize = 3 + 1 + 32;

/// The tag of a **forced intent**: a signed submission the sequencer must
/// apply, carried to the vault on a small note because the sequencer's own
/// door was shut. Distinct in its first bytes from both other tags.
pub const FORCED_TAG: &[u8; 3] = b"ZYF";
/// tag + version + length; the frame follows, then zero padding.
pub const FORCED_HEADER: usize = 3 + 1 + 2;
/// The most frame a memo can carry.
pub const FORCED_MAX: usize = MEMO_FIELD - FORCED_HEADER;

/// A Cave sale payment. This is deliberately not a normal `ZEC` deposit:
/// accepting the same note through both paths would mint buyer credit while
/// also treating the ZEC as NFT-sale proceeds.
pub const CAVE_PAYMENT_TAG: &[u8; 3] = b"ZYC";
/// Cave payment memo version.
pub const CAVE_PAYMENT_VERSION: u8 = 1;
/// tag + version + purpose + committed reference + recipient.
pub const CAVE_PAYMENT_LEN: usize = 3 + 1 + 1 + 32 + 32;

/// Why the Cave payment was made. The reference is a policy digest for an
/// entry and an allocation ticket id for a claim.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CavePaymentPurpose {
    Entry,
    Claim,
}

impl CavePaymentPurpose {
    fn code(self) -> u8 {
        match self {
            Self::Entry => 1,
            Self::Claim => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Entry),
            2 => Some(Self::Claim),
            _ => None,
        }
    }
}

/// The application binding carried by a Cave ZEC payment.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CavePaymentMemo {
    pub purpose: CavePaymentPurpose,
    pub reference: [u8; 32],
    pub recipient: AccountId,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CavePaymentError {
    NotCavePayment,
    UnknownVersion(u8),
    UnknownPurpose(u8),
    Malformed,
    TrailingBytes,
}

/// Whether these bytes claim the Cave namespace, valid or not. Callers use
/// this to fail closed: a malformed `ZYC` instruction must never fall through
/// and become an ordinary bridge credit by address attribution.
pub fn has_cave_payment_tag(memo: &[u8]) -> bool {
    memo.len() >= 3 && &memo[..3] == CAVE_PAYMENT_TAG
}

/// Build the memo for a purpose-bound Cave payment. Zero references and zero
/// recipients are refused because neither can identify a sale obligation.
pub fn encode_cave_payment(payment: CavePaymentMemo) -> Result<[u8; MEMO_FIELD], CavePaymentError> {
    if payment.reference == [0; 32] || payment.recipient == [0; 32] {
        return Err(CavePaymentError::Malformed);
    }
    let mut out = [0u8; MEMO_FIELD];
    out[..3].copy_from_slice(CAVE_PAYMENT_TAG);
    out[3] = CAVE_PAYMENT_VERSION;
    out[4] = payment.purpose.code();
    out[5..37].copy_from_slice(&payment.reference);
    out[37..CAVE_PAYMENT_LEN].copy_from_slice(&payment.recipient);
    Ok(out)
}

/// Parse a Cave payment without ever accepting it as an ordinary bridge
/// deposit. Like the bridge memo, all bytes after the instruction must be zero.
pub fn decode_cave_payment(memo: &[u8]) -> Result<CavePaymentMemo, CavePaymentError> {
    if !has_cave_payment_tag(memo) {
        return Err(CavePaymentError::NotCavePayment);
    }
    if memo.len() < CAVE_PAYMENT_LEN {
        return Err(CavePaymentError::Malformed);
    }
    if memo[3] != CAVE_PAYMENT_VERSION {
        return Err(CavePaymentError::UnknownVersion(memo[3]));
    }
    let purpose =
        CavePaymentPurpose::from_code(memo[4]).ok_or(CavePaymentError::UnknownPurpose(memo[4]))?;
    if memo[CAVE_PAYMENT_LEN..].iter().any(|byte| *byte != 0) {
        return Err(CavePaymentError::TrailingBytes);
    }
    let reference = memo[5..37]
        .try_into()
        .map_err(|_| CavePaymentError::Malformed)?;
    let recipient = memo[37..CAVE_PAYMENT_LEN]
        .try_into()
        .map_err(|_| CavePaymentError::Malformed)?;
    if reference == [0; 32] || recipient == [0; 32] {
        return Err(CavePaymentError::Malformed);
    }
    Ok(CavePaymentMemo {
        purpose,
        reference,
        recipient,
    })
}

/// Wrap a signed submission frame for the memo. `None` if it does not fit.
pub fn encode_forced(frame: &[u8]) -> Option<[u8; MEMO_FIELD]> {
    if frame.is_empty() || frame.len() > FORCED_MAX {
        return None;
    }
    let mut out = [0u8; MEMO_FIELD];
    out[..3].copy_from_slice(FORCED_TAG);
    out[3] = MEMO_VERSION;
    out[4..6].copy_from_slice(&(frame.len() as u16).to_be_bytes());
    out[FORCED_HEADER..FORCED_HEADER + frame.len()].copy_from_slice(frame);
    Some(out)
}

/// The frame inside a forced memo, or `None` if the memo is not one. Strict
/// like `decode`: the declared length must fit and the padding must be zero.
pub fn forced_frame(memo: &[u8]) -> Option<&[u8]> {
    if memo.len() < FORCED_HEADER || &memo[..3] != FORCED_TAG || memo[3] != MEMO_VERSION {
        return None;
    }
    let len = u16::from_be_bytes([memo[4], memo[5]]) as usize;
    if len == 0 || FORCED_HEADER + len > memo.len() {
        return None;
    }
    if memo[FORCED_HEADER + len..].iter().any(|b| *b != 0) {
        return None;
    }
    Some(&memo[FORCED_HEADER..FORCED_HEADER + len])
}

/// Who a frame is from, read off its key without checking the signature —
/// enough to credit the note that carried it to the right account. `None`
/// for a scheme whose account needs signature recovery (EVM), which a
/// forced memo does not support.
pub fn forced_account(frame: &[u8]) -> Option<AccountId> {
    use crate::account::Scheme;
    // vm_id[32] ‖ valid_until u64 ‖ scheme u8 ‖ key[32] ‖ …
    if frame.len() < 32 + 8 + 1 + 32 {
        return None;
    }
    let scheme = Scheme::from_tag(frame[40])?;
    match scheme {
        Scheme::Ed25519 | Scheme::Ed25519Message => {
            Some(crate::account::account_of(scheme, &frame[41..73]))
        }
        _ => None,
    }
}

/// Whether a memo is an anchor: the tag, the version, the length, and nothing
/// but zero padding after it. The scanner uses this to keep an anchor out of
/// the deposit path without knowing anything else about anchors.
pub fn is_anchor(memo: &[u8]) -> bool {
    memo.len() >= ANCHOR_LEN
        && &memo[..3] == ANCHOR_TAG
        && memo[3] == MEMO_VERSION
        && memo[ANCHOR_LEN..].iter().all(|b| *b == 0)
}

/// The 512-byte memo field publishing `digest`.
pub fn encode_publication(digest: &[u8; 32]) -> [u8; MEMO_FIELD] {
    let mut out = [0u8; MEMO_FIELD];
    out[..3].copy_from_slice(PUBLISH_TAG);
    out[3] = MEMO_VERSION;
    out[4..PUBLISH_LEN].copy_from_slice(digest);
    out
}

/// The digest a publication memo carries, if it is one.
///
/// Strict about the padding for the same reason `is_anchor` is: a memo that
/// carries a digest *and* something else is not a publication, and reading one
/// out of it would let a single transaction be claimed as publishing several
/// different things.
pub fn publication(memo: &[u8]) -> Option<[u8; 32]> {
    if memo.len() < PUBLISH_LEN
        || &memo[..3] != PUBLISH_TAG
        || memo[3] != MEMO_VERSION
        || !memo[PUBLISH_LEN..].iter().all(|b| *b == 0)
    {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&memo[4..PUBLISH_LEN]);
    Some(out)
}

/// Whether a memo is a publication. Used by the scanner to keep it out of the
/// deposit path without knowing what it commits to.
pub fn is_publication(memo: &[u8]) -> bool {
    publication(memo).is_some()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoError {
    /// Not a Zyn deposit instruction at all — no tag. The overwhelmingly common
    /// case: an empty memo, a wallet default, a note to a human.
    NotADeposit,
    /// Tagged, but a version this build does not know. Refused rather than
    /// guessed at: a later version may mean something different by these bytes.
    UnknownVersion(u8),
    /// Tagged and versioned, but the wrong length.
    Malformed,
    /// Padding after the instruction was not zero. Refused because it is the
    /// difference between a memo that says one thing and a memo that says one
    /// thing and also carries something else.
    TrailingBytes,
}

/// Build the memo a depositor must send.
///
/// A wallet or a UI produces this; a human should never be typing it.
pub fn encode(account: &AccountId) -> [u8; MEMO_FIELD] {
    let mut out = [0u8; MEMO_FIELD];
    out[..3].copy_from_slice(MEMO_TAG);
    out[3] = MEMO_VERSION;
    out[4..MEMO_LEN].copy_from_slice(account);
    out
}

/// Read the account a memo names.
///
/// Accepts the memo at any length from `MEMO_LEN` up, since wallets differ in
/// whether they pad — but everything past the instruction must be zero.
pub fn decode(memo: &[u8]) -> Result<AccountId, MemoError> {
    // The text form, typed into a wallet: `ZEC1:<hex>` then zero padding. The
    // binary form below is what a UI would build; nobody can type a 0x01.
    if memo.len() >= 5 && &memo[..5] == b"ZEC1:" {
        let end = memo.iter().position(|b| *b == 0).unwrap_or(memo.len());
        let text = core::str::from_utf8(&memo[..end]).map_err(|_| MemoError::Malformed)?;
        if memo[end..].iter().any(|b| *b != 0) {
            return Err(MemoError::TrailingBytes);
        }
        return decode_text(text);
    }
    if memo.len() < MEMO_LEN || &memo[..3] != MEMO_TAG {
        return Err(MemoError::NotADeposit);
    }
    if memo[3] != MEMO_VERSION {
        return Err(MemoError::UnknownVersion(memo[3]));
    }
    if memo[MEMO_LEN..].iter().any(|b| *b != 0) {
        return Err(MemoError::TrailingBytes);
    }
    let account: AccountId = memo[4..MEMO_LEN]
        .try_into()
        .map_err(|_| MemoError::Malformed)?;
    Ok(account)
}

/// The same instruction as text, for chains whose memo is a string.
///
/// Ed25519's Memo program carries UTF-8, not a fixed-width field, so the binary
/// form above has nowhere to live there. This is the same tag, the same
/// version and the same strictness in a form a person can read in a block
/// explorer — which matters, because on Ed25519 the memo is public.
///
/// ```text
///   ZEC1:<64 lowercase hex>
/// ```
///
/// Hex rather than base58 or base64 deliberately: it is fixed-length, so a
/// truncated memo is a length error rather than a different valid account, and
/// it is the encoding the rest of this workspace already uses for accounts.
pub fn encode_text(account: &AccountId) -> String {
    let mut s = String::with_capacity(5 + 64);
    s.push_str(core::str::from_utf8(MEMO_TAG).unwrap_or("ZEC"));
    s.push((b'0' + MEMO_VERSION) as char);
    s.push(':');
    for b in account {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Read the account a text memo names.
///
/// Case-insensitive in the hex and tolerant of surrounding whitespace, because
/// both survive a round trip through a wallet's input box. Nothing else is
/// tolerated: a memo that is *nearly* right is a manual refund, not a guess.
pub fn decode_text(memo: &str) -> Result<AccountId, MemoError> {
    let m = memo.trim();
    let tag = core::str::from_utf8(MEMO_TAG).unwrap_or("ZEC");
    let rest = m.strip_prefix(tag).ok_or(MemoError::NotADeposit)?;
    let (v, hex) = rest.split_at_checked(1).ok_or(MemoError::NotADeposit)?;
    let version = v.as_bytes()[0].wrapping_sub(b'0');
    if !v.as_bytes()[0].is_ascii_digit() {
        return Err(MemoError::NotADeposit);
    }
    if version != MEMO_VERSION {
        return Err(MemoError::UnknownVersion(version));
    }
    let hex = hex.strip_prefix(':').ok_or(MemoError::Malformed)?;
    if hex.len() != 64 {
        return Err(MemoError::Malformed);
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| MemoError::Malformed)?;
    }
    Ok(out)
}

/// The operator top-up memo: a `ZEC` memo naming the all-zero account.
///
/// Classified as "a top-up of the vault by the operator (to cover fees), held,
/// never credited" — the only way to put ZEC behind anchor fees without
/// minting ZEC.zy against it. Named rather than left as `encode(&[0u8; 32])`
/// so the intent is legible at the call site and cannot be mistaken for a
/// deposit to a real account.
pub const TOPUP_ACCOUNT: AccountId = [0u8; 32];

/// Whether this memo is an operator top-up rather than a deposit.
pub fn is_topup(memo: &[u8]) -> bool {
    decode(memo).map(|a| a == TOPUP_ACCOUNT).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    /// The top-up memo must be recognisable and must not look like a deposit to
    /// a real account — the difference decides whether ZEC.zy is minted.
    #[test]
    fn a_topup_memo_names_nobody_and_is_told_apart_from_a_deposit() {
        let topup = encode(&TOPUP_ACCOUNT);
        assert!(is_topup(&topup));
        assert_eq!(decode(&topup).unwrap(), [0u8; 32]);

        let real = encode(&[9u8; 32]);
        assert!(!is_topup(&real), "a deposit to a real account is not a top-up");

        // The text form the wallet sends must round-trip to the same thing.
        assert!(is_topup(encode_text(&TOPUP_ACCOUNT).as_bytes()));
    }

    use super::*;

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }

    #[test]
    fn a_memo_round_trips() {
        for n in [0u8, 1, 200, 255] {
            assert_eq!(decode(&encode(&acct(n))), Ok(acct(n)));
        }
        // And is unpadded-tolerant, since wallets differ.
        let m = encode(&acct(7));
        assert_eq!(decode(&m[..MEMO_LEN]), Ok(acct(7)));
    }

    /// The common case by a wide margin, and it must never be a deposit.
    #[test]
    fn an_ordinary_memo_is_not_a_deposit() {
        for memo in [
            &b""[..],
            &b"thanks!"[..],
            &b"sent from my wallet"[..],
            &[0u8; 512][..],
            // Thirty-two bytes of something that is not an instruction.
            &[0xABu8; 32][..],
        ] {
            assert_eq!(
                decode(memo),
                Err(MemoError::NotADeposit),
                "memo {:?} was read",
                memo
            );
        }
    }

    /// A later version may mean something different by the same bytes, so an
    /// unknown one is refused rather than read hopefully.
    #[test]
    fn an_unknown_version_is_refused_not_guessed() {
        let mut m = encode(&acct(1));
        m[3] = 2;
        assert_eq!(decode(&m), Err(MemoError::UnknownVersion(2)));
    }

    /// Anything after the instruction must be zero — otherwise a memo could say
    /// one thing and carry another, and two readers could disagree about which
    /// part counts.
    #[test]
    fn a_memo_carrying_extra_is_refused() {
        let mut m = encode(&acct(1));
        m[MEMO_LEN] = 0x01;
        assert_eq!(decode(&m), Err(MemoError::TrailingBytes));
        m[MEMO_LEN] = 0;
        m[511] = 0xFF;
        assert_eq!(decode(&m), Err(MemoError::TrailingBytes));
    }

    /// Tagged but truncated: the tag alone must not be enough to be read as an
    /// instruction.
    #[test]
    fn a_truncated_instruction_is_not_a_deposit() {
        let m = encode(&acct(1));
        for cut in 0..MEMO_LEN {
            assert!(decode(&m[..cut]).is_err(), "a memo cut at {} decoded", cut);
        }
    }

    #[test]
    fn a_text_memo_round_trips() {
        for n in [0u8, 1, 200, 255] {
            assert_eq!(decode_text(&encode_text(&acct(n))), Ok(acct(n)));
        }
        assert_eq!(encode_text(&acct(0)), format!("ZEC1:{}", "00".repeat(32)));
        // Whitespace and case survive a wallet's input box; nothing else does.
        assert_eq!(
            decode_text("  ZEC1:AB{}  ".replace("{}", &"ab".repeat(31)).as_str()),
            decode_text(&format!("ZEC1:ab{}", "ab".repeat(31)))
        );
    }

    /// On Ed25519 the memo is public and typed by whoever sends it, so the
    /// near-misses are what this has to survive.
    #[test]
    fn a_text_memo_that_is_nearly_right_is_refused() {
        let ok = encode_text(&acct(3));
        assert_eq!(decode_text(""), Err(MemoError::NotADeposit));
        assert_eq!(decode_text("gm"), Err(MemoError::NotADeposit));
        assert_eq!(decode_text("ZEC"), Err(MemoError::NotADeposit));
        assert_eq!(decode_text("ZECX:00"), Err(MemoError::NotADeposit));
        assert_eq!(
            decode_text(&ok.replace("ZEC1", "ZEC2")),
            Err(MemoError::UnknownVersion(2))
        );
        assert_eq!(decode_text(&ok[..ok.len() - 1]), Err(MemoError::Malformed));
        assert_eq!(decode_text(&format!("{}0", ok)), Err(MemoError::Malformed));
        assert_eq!(
            decode_text(&ok.replace(':', ";")),
            Err(MemoError::Malformed)
        );
        // A non-hex character in the right place must not decode as something.
        assert_eq!(
            decode_text(&format!("ZEC1:zz{}", "ab".repeat(31))),
            Err(MemoError::Malformed)
        );
    }

    /// A wallet's memo box takes text. The same instruction typed there, in
    /// a 512-byte field padded with zeros, must credit the same account.
    #[test]
    fn a_typed_text_memo_is_accepted_by_the_binary_decoder() {
        let text = encode_text(&acct(9));
        let mut field = [0u8; MEMO_FIELD];
        field[..text.len()].copy_from_slice(text.as_bytes());
        assert_eq!(decode(&field), Ok(acct(9)));
        assert_eq!(
            decode(text.as_bytes()),
            Ok(acct(9)),
            "unpadded, as some wallets send"
        );
        // Text after the instruction is not padding.
        let mut noisy = field;
        noisy[text.len()] = b' ';
        noisy[text.len() + 1] = b'x';
        assert!(decode(&noisy).is_err());
    }

    #[test]
    fn an_anchor_memo_is_not_a_deposit_and_a_deposit_is_not_an_anchor() {
        let mut anchor = [0u8; MEMO_FIELD];
        anchor[..3].copy_from_slice(ANCHOR_TAG);
        anchor[3] = MEMO_VERSION;
        anchor[4..ANCHOR_LEN].copy_from_slice(&[7u8; ANCHOR_LEN - 4]);
        assert!(is_anchor(&anchor));
        assert_eq!(decode(&anchor), Err(MemoError::NotADeposit));
        let deposit = encode(&[9u8; 32]);
        assert!(!is_anchor(&deposit));
        assert_eq!(decode(&deposit), Ok([9u8; 32]));
        let mut trailing = anchor;
        trailing[ANCHOR_LEN] = 1;
        assert!(
            !is_anchor(&trailing),
            "an anchor with trailing bytes is not an anchor"
        );
    }

    #[test]
    fn a_forced_memo_is_neither_a_deposit_nor_an_anchor_and_round_trips_its_frame() {
        let mut frame = vec![0u8; 32 + 8 + 1 + 32 + 64 + 7];
        frame[40] = crate::account::Scheme::Ed25519.tag();
        frame[41..73].copy_from_slice(&[0x33u8; 32]);
        let memo = encode_forced(&frame).unwrap();
        assert_eq!(forced_frame(&memo), Some(frame.as_slice()));
        assert_eq!(decode(&memo), Err(MemoError::NotADeposit));
        assert!(!is_anchor(&memo));
        assert_eq!(
            forced_account(&frame),
            Some(crate::account::account_of(
                crate::account::Scheme::Ed25519,
                &[0x33u8; 32]
            ))
        );
        assert!(forced_frame(&encode(&[1u8; 32])).is_none());
        let mut bad = memo;
        bad[MEMO_FIELD - 1] = 1;
        assert!(forced_frame(&bad).is_none(), "trailing bytes");
        assert!(encode_forced(&[0u8; FORCED_MAX + 1]).is_none(), "too big");
        assert!(encode_forced(&[]).is_none());
    }

    #[test]
    fn cave_payments_are_strict_and_never_decode_as_buyer_deposits() {
        for purpose in [CavePaymentPurpose::Entry, CavePaymentPurpose::Claim] {
            let payment = CavePaymentMemo {
                purpose,
                reference: [0x44; 32],
                recipient: [0x55; 32],
            };
            let memo = encode_cave_payment(payment).unwrap();
            assert_eq!(decode_cave_payment(&memo), Ok(payment));
            assert_eq!(decode(&memo), Err(MemoError::NotADeposit));
            assert!(!is_anchor(&memo));
            assert!(forced_frame(&memo).is_none());
        }

        assert_eq!(
            encode_cave_payment(CavePaymentMemo {
                purpose: CavePaymentPurpose::Entry,
                reference: [0; 32],
                recipient: [1; 32],
            }),
            Err(CavePaymentError::Malformed)
        );
        let mut memo = encode_cave_payment(CavePaymentMemo {
            purpose: CavePaymentPurpose::Entry,
            reference: [1; 32],
            recipient: [2; 32],
        })
        .unwrap();
        memo[CAVE_PAYMENT_LEN] = 1;
        assert_eq!(
            decode_cave_payment(&memo),
            Err(CavePaymentError::TrailingBytes)
        );
        assert!(decode_cave_payment(&memo[..CAVE_PAYMENT_LEN - 1]).is_err());
        memo[CAVE_PAYMENT_LEN] = 0;
        memo[3] = 2;
        assert_eq!(
            decode_cave_payment(&memo),
            Err(CavePaymentError::UnknownVersion(2))
        );
        memo[3] = CAVE_PAYMENT_VERSION;
        memo[4] = 9;
        assert_eq!(
            decode_cave_payment(&memo),
            Err(CavePaymentError::UnknownPurpose(9))
        );
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    const D: [u8; 32] = [0x5c; 32];

    #[test]
    fn a_publication_round_trips_and_is_zero_padded() {
        let m = encode_publication(&D);
        assert_eq!(m.len(), MEMO_FIELD);
        assert_eq!(publication(&m), Some(D));
        assert!(is_publication(&m));
        assert!(m[PUBLISH_LEN..].iter().all(|b| *b == 0));
    }

    /// Strict padding, for the reason `is_anchor` is strict: a memo carrying a
    /// digest *and* something else is not a publication, and reading one out of
    /// it would let a single transaction be claimed as publishing several
    /// different things.
    #[test]
    fn trailing_bytes_disqualify_it() {
        let mut m = encode_publication(&D);
        m[PUBLISH_LEN] = 1;
        assert_eq!(publication(&m), None);
        assert!(!is_publication(&m));
    }

    /// The three vault-stamped namespaces must not be mistaken for each other,
    /// or a deposit could be read as a publication and never credited — or
    /// worse, the reverse.
    #[test]
    fn a_publication_is_not_an_anchor_and_not_a_deposit() {
        let m = encode_publication(&D);
        assert!(!is_anchor(&m));
        assert!(!has_cave_payment_tag(&m));
        assert!(decode(&m).is_err(), "not an account memo either");

        // And nothing else is a publication.
        assert!(!is_publication(&encode(&[7u8; 32])));
        assert!(!is_publication(&[0u8; MEMO_FIELD]));
        assert!(!is_publication(b"ZYP"), "the tag alone is not a digest");
    }

    #[test]
    fn a_wrong_version_is_refused_rather_than_guessed() {
        let mut m = encode_publication(&D);
        m[3] = MEMO_VERSION + 1;
        assert_eq!(publication(&m), None);
    }

    #[test]
    fn every_digest_gives_a_different_memo() {
        let mut other = D;
        other[31] ^= 1;
        assert_ne!(encode_publication(&D), encode_publication(&other));
        assert_eq!(publication(&encode_publication(&other)), Some(other));
    }
}
