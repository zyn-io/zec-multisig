//! base58 and base58check, as Zcash transparent addresses use.
//!
//! Hand-rolled for the reason the transaction bytes are: it is thirty lines,
//! the alternative is a dependency tree, and an address that decodes wrongly
//! here pays the wrong person.

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut big: Vec<u8> = Vec::new(); // little-endian base-256 accumulator
    for c in s.bytes() {
        let d = B58.iter().position(|x| *x == c)? as u32;
        let mut carry = d;
        for b in big.iter_mut() {
            let v = (*b as u32) * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            big.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|c| *c == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(big.iter().rev());
    Some(out)
}

pub fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new(); // little-endian base-58
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 58) as u8;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for _ in bytes.iter().take_while(|b| **b == 0) {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(B58[*d as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_keeps_leading_zeros() {
        for case in [vec![0u8, 0, 1, 2, 3], vec![255; 20], vec![0; 4]] {
            assert_eq!(base58_decode(&base58_encode(&case)).unwrap(), case);
        }
    }
}
