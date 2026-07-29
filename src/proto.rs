//! Host framing for NSCCN wCopy-family readers. See `docs/PROTOCOL.md`.
//!
//! ```text
//! off  value
//! 0    0x00                 hidapi report-ID byte, absent on the wire
//! 1    0x01 out / 0x02 in   direction magic
//! 2    LEN = payload+6      counts offsets 1..=LEN
//! 3    seq & 0xff           16-bit LE, host increments by 2 per send
//! 4    seq >> 8
//! 5..  payload
//! 5+n  checksum
//! 6+n  0xFE out / 0xFD in
//! ```

pub const VID: u16 = 0x2518;
pub const PID: u16 = 0x6018;

pub const REPORT: usize = 64;
const BUF: usize = REPORT + 1;
pub const MAX_PAYLOAD: usize = BUF - 7;

const MAGIC_TX: u8 = 0x01;
const MAGIC_RX: u8 = 0x02;
const TRAILER_TX: u8 = 0xFE;
const TRAILER_RX: u8 = 0xFD;

fn checksum(frame: &[u8], n: usize) -> u8 {
    !frame[1..=n + 4].iter().fold(0u8, |a, b| a.wrapping_add(*b))
}

pub fn encode(payload: &[u8], seq: u16) -> Result<[u8; BUF], String> {
    let n = payload.len();
    if n > MAX_PAYLOAD {
        return Err(format!("payload {n} exceeds {MAX_PAYLOAD}"));
    }
    let mut f = [0u8; BUF];
    f[1] = MAGIC_TX;
    f[2] = (n + 6) as u8;
    f[3] = seq as u8;
    f[4] = (seq >> 8) as u8;
    f[5..5 + n].copy_from_slice(payload);
    f[5 + n] = checksum(&f, n);
    f[6 + n] = TRAILER_TX;
    Ok(f)
}

#[derive(Debug)]
pub struct Reply {
    pub payload: Vec<u8>,
    pub seq: u16,
    pub checksum_ok: bool,
    pub trailer_ok: bool,
}

pub fn decode(report: &[u8]) -> Result<Reply, String> {
    if report.len() < 7 {
        return Err(format!("short report ({} bytes)", report.len()));
    }
    if report[0] != MAGIC_RX {
        return Err(format!(
            "magic {:#04x}, expected {MAGIC_RX:#04x}",
            report[0]
        ));
    }
    // Replies carry no report-ID byte. Re-align onto a scratch buffer so the
    // offsets match `encode` and checksum() can be reused
    let mut f = [0u8; BUF];
    let len = report[1] as usize;
    if len < 6 || len > report.len() {
        return Err(format!("implausible length byte {len:#04x}"));
    }
    let n = len - 6;
    f[1..=len].copy_from_slice(&report[..len]);

    Ok(Reply {
        payload: f[5..5 + n].to_vec(),
        seq: u16::from_le_bytes([f[3], f[4]]),
        checksum_ok: f[5 + n] == checksum(&f, n),
        trailer_ok: f[6 + n] == TRAILER_RX,
    })
}

/// `ff 00 65 08 <lc> <freq LE32> <w1 LE16> <w2 LE16>`, from 0x408cc0.
///
/// `lc` sits where an APDU length byte belongs but is not one. The vendor pairs
/// one value with each carrier
pub fn lf_read(freq: u32, lc: u8, w1: u16, w2: u16) -> Vec<u8> {
    let mut p = vec![0xff, 0x00, 0x65, 0x08, lc];
    p.extend_from_slice(&freq.to_le_bytes());
    p.extend_from_slice(&w1.to_le_bytes());
    p.extend_from_slice(&w2.to_le_bytes());
    p
}

/// Every profile the vendor's auto-detect sweeps, in order; an EM4100
/// answers the first
pub const LF_PROFILES: [(u32, u8, u16, u16); 10] = [
    (125_000, 0x18, 0, 0),
    (250_000, 0x04, 0, 0),
    (375_000, 0x02, 0, 0),
    (500_000, 0x01, 0x005d, 0x004b),
    (125_000, 0x18, 0x0181, 0x0118),
    (175_000, 0x04, 0x00bb, 0x0096),
    (250_000, 0x04, 0x00bb, 0x0096),
    (300_000, 0x04, 0x00bb, 0x0096),
    (375_000, 0x02, 0x008b, 0x0070),
    (500_000, 0x01, 0x005d, 0x004b),
];

pub fn lf_id(payload: &[u8]) -> Option<[u8; 5]> {
    match payload {
        [5, rest @ ..] if rest.len() >= 5 => Some(rest[..5].try_into().unwrap()),
        _ => None,
    }
}

pub const VENDOR_KEY: [u8; 4] = [0x54, 0x69, 0x61, 0x6e];

pub fn lf_read_block(freq: u32, blk: u8) -> Vec<u8> {
    let mut p = vec![0xff, 0x00, 0x66, 0x00, 0x1e];
    p.extend_from_slice(&freq.to_le_bytes());
    p.extend_from_slice(&[0x12, 0x00, blk, 0, 0, 0, 0]);
    p
}

/// `ff 00 66 00 1e <freq LE32> 13 00 <blk> <data> <key>`, from 0x40c440
pub fn lf_write_block(freq: u32, blk: u8, data: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0xff, 0x00, 0x66, 0x00, 0x1e];
    p.extend_from_slice(&freq.to_le_bytes());
    p.extend_from_slice(&[0x13, 0x00, blk]);
    p.extend_from_slice(&data);
    p.extend_from_slice(&VENDOR_KEY);
    p
}

/// Nine 1 bits, each of the ten nibbles followed by its own even parity bit,
/// four column parity bits across the nibbles, a 0 stop bit. 9 + 50 + 4 + 1.
pub fn em4100_frame(id: [u8; 5]) -> u64 {
    let mut f: u64 = 0x1ff;
    let mut col = [0u8; 4];
    for nib in id.iter().flat_map(|b| [b >> 4, b & 0x0f]) {
        let mut row = 0;
        for (pos, c) in col.iter_mut().enumerate() {
            let bit = nib >> (3 - pos) & 1;
            *c ^= bit;
            row ^= bit;
            f = f << 1 | bit as u64;
        }
        f = f << 1 | row as u64;
    }
    for c in col {
        f = f << 1 | c as u64;
    }
    f << 1
}

/// `ff 00 00 00 <lc> d4 <cmd...>`. `0xd4` is the host-to-controller TFI.
/// Replies come back `d5 <cmd+1> ...`
pub fn pn532(cmd: &[u8]) -> Vec<u8> {
    let mut p = vec![0xff, 0x00, 0x00, 0x00, (cmd.len() + 1) as u8, 0xd4];
    p.extend_from_slice(cmd);
    p
}

/// The body of a `d5 <cmd+1> <body...> 90 00` reply.
///
/// Byte 0 of the body left alone. Only the exchange commands put a status
/// there; GetFirmwareVersion starts its data immediately, and reading byte 0 as
/// a status would take its `0x32` for an error.
pub fn pn532_data(payload: &[u8]) -> Result<&[u8], String> {
    let body = payload
        .strip_suffix(&[0x90, 0x00])
        .ok_or_else(|| format!("no 90 00 status word: {}", hex(payload)))?;
    match body {
        [0xd5, _, rest @ ..] => Ok(rest),
        _ => Err(format!("not a PN532 reply: {}", hex(body))),
    }
}

pub fn exchange_data(payload: &[u8]) -> Result<&[u8], String> {
    match pn532_data(payload)? {
        [0x00, rest @ ..] => Ok(rest),
        [0x14, ..] => Err("authentication failed (wrong key)".into()),
        [err, ..] => Err(format!("PN532 error {err:#04x}")),
        [] => Err("empty exchange reply".into()),
    }
}

pub fn in_data_exchange(cmd: &[u8]) -> Vec<u8> {
    let mut v = vec![0x40, 0x01];
    v.extend_from_slice(cmd);
    pn532(&v)
}

pub fn hf_detect() -> Vec<u8> {
    vec![0xff, 0x00, 0x6a, 0x01, 0x00, 0x08]
}

pub fn hf_activate() -> Vec<u8> {
    vec![0xff, 0x00, 0x61, 0x01]
}

pub fn hf_release() -> Vec<u8> {
    vec![0xff, 0x00, 0x62, 0x01, 0x00]
}

/// Key A is `0x60`, key B is `0x61`. The UID's first four bytes feed the crypto1
/// nonce and travel alongside the key.
pub fn mifare_auth(key_b: bool, blk: u8, key: [u8; 6], uid: [u8; 4]) -> Vec<u8> {
    let mut v = vec![if key_b { 0x61 } else { 0x60 }, blk];
    v.extend_from_slice(&key);
    v.extend_from_slice(&uid);
    in_data_exchange(&v)
}

pub fn mifare_read(blk: u8) -> Vec<u8> {
    in_data_exchange(&[0x30, blk])
}

pub fn mifare_write(blk: u8, data: [u8; 16]) -> Vec<u8> {
    let mut v = vec![0xa0, blk];
    v.extend_from_slice(&data);
    in_data_exchange(&v)
}

/// Sectors 0-31 hold four blocks, 32-39 hold sixteen.
pub fn sector_blocks(sector: u8) -> std::ops::RangeInclusive<u8> {
    if sector < 32 {
        let first = sector * 4;
        first..=first + 3
    } else {
        let first = 128 + (sector - 32) * 16;
        first..=first + 15
    }
}

/// The last block of a sector, holding key A, the access bits and key B.
/// ! A wrong value here locks the sector permanently !
pub fn is_trailer(blk: u8) -> bool {
    if blk < 128 {
        blk % 4 == 3
    } else {
        (blk - 128) % 16 == 15
    }
}

pub fn beep(dur: u8) -> Vec<u8> {
    vec![0xff, 0x00, 0x40, 0x50, 0x04, 0x01, dur, 0x01, 0x01]
}

/// The ways an EM4100 ID gets persisted, from the vendor's format strings at
/// 0x43af26 and 0x43af74. The decimal forms describe only part of the 40 bits;
/// converting needs the rest of the ID to fall back on
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdForm {
    Hex,
    /// Bytes 1-4 as one big-endian u32, ten digits
    Dec10,
    /// Byte 2 as three digits, then bytes 3-4 as a u16 in five digits
    Dec35,
}

impl IdForm {
    pub const ALL: [IdForm; 3] = [Self::Hex, Self::Dec10, Self::Dec35];

    pub fn label(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Dec10 => "dec10",
            Self::Dec35 => "dec3+5",
        }
    }

    /// Which bytes this form sets
    pub fn covers(self) -> &'static str {
        match self {
            Self::Hex => "Sets all five bytes.",
            Self::Dec10 => "Sets bytes 1-4. Byte 0 keeps its current value.",
            Self::Dec35 => "Sets bytes 2-4. Bytes 0 and 1 keep their current values.",
        }
    }
}

pub fn em4100_show(id: [u8; 5], form: IdForm) -> String {
    match form {
        IdForm::Hex => hex(&id),
        IdForm::Dec10 => format!("{:010}", u32::from_be_bytes([id[1], id[2], id[3], id[4]])),
        IdForm::Dec35 => format!("{:03}{:05}", id[2], u16::from_be_bytes([id[3], id[4]])),
    }
}

/// `base` supplies the bytes the form doesn't mention
pub fn em4100_parse(s: &str, form: IdForm, base: [u8; 5]) -> Result<[u8; 5], String> {
    let t = s.trim();
    let mut id = base;
    match form {
        IdForm::Hex => {
            let v = unhex(t)?;
            if v.len() != 5 {
                return Err(format!("an ID is 5 bytes, got {}", v.len()));
            }
            id.copy_from_slice(&v);
        }
        IdForm::Dec10 => {
            let n: u32 = t.parse().map_err(|_| format!("{t:?} is not a number"))?;
            id[1..5].copy_from_slice(&n.to_be_bytes());
        }
        IdForm::Dec35 => {
            if t.len() != 8 || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err("dec3+5 is exactly 8 digits, e.g. 08630874".into());
            }
            let cc: u8 = t[..3].parse().map_err(|_| "first 3 digits exceed 255")?;
            let lo: u16 = t[3..].parse().map_err(|_| "last 5 digits exceed 65535")?;
            id[2] = cc;
            id[3..5].copy_from_slice(&lo.to_be_bytes());
        }
    }
    Ok(id)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    s.split_whitespace()
        .flat_map(|t| t.strip_prefix("0x").unwrap_or(t).as_bytes().chunks(2))
        .map(|c| {
            let t = std::str::from_utf8(c).map_err(|e| e.to_string())?;
            u8::from_str_radix(t, 16).map_err(|e| format!("bad hex {t:?}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips() {
        let f = encode(&unhex("ff 00 00 00 02 d4 02").unwrap(), 0).unwrap();
        assert_eq!(hex(&f[..14]), "00 01 0d 00 00 ff 00 00 00 02 d4 02 1a fe");

        let r = decode(&unhex("02 0e 01 00 d5 03 32 01 06 07 90 00 46 fd").unwrap()).unwrap();
        assert!(r.checksum_ok && r.trailer_ok);
        assert_eq!(hex(&r.payload), "d5 03 32 01 06 07 90 00");
        assert_eq!(r.seq, 1, "device answers seq+1");
    }

    #[test]
    fn lf_id_needs_the_length_byte() {
        assert_eq!(
            lf_id(&unhex("05 12 34 56 78 9a").unwrap()),
            Some([0x12, 0x34, 0x56, 0x78, 0x9a])
        );
        assert_eq!(lf_id(&unhex("00").unwrap()), None);
        assert_eq!(lf_id(&unhex("05 12 34").unwrap()), None);
    }

    #[test]
    fn builds_a_block_write() {
        let p = lf_write_block(125_000, 1, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            hex(&p),
            "ff 00 66 00 1e 48 e8 01 00 13 00 01 de ad be ef 54 69 61 6e"
        );
        assert_eq!(p.len(), 20);
    }

    #[test]
    fn em4100_frame_round_trips() {
        let id = [0x04, 0x91, 0x7c, 0x2a, 0xf3];
        let f = em4100_frame(id);
        assert_eq!(f >> 55, 0x1ff, "nine header ones");
        assert_eq!(f & 1, 0, "stop bit");

        let mut nibbles = [0u8; 10];
        let mut col = [0u8; 4];
        for (i, nib) in nibbles.iter_mut().enumerate() {
            let group = (f >> (50 - i * 5)) & 0x1f;
            let (data, parity) = ((group >> 1) as u8, (group & 1) as u8);
            assert_eq!(data.count_ones() as u8 % 2, parity, "row parity {i}");
            for (pos, c) in col.iter_mut().enumerate() {
                *c ^= data >> (3 - pos) & 1;
            }
            *nib = data;
        }
        for (pos, c) in col.iter().enumerate() {
            assert_eq!(f >> (4 - pos) & 1, *c as u64, "column parity {pos}");
        }
        let decoded: Vec<u8> = nibbles.chunks(2).map(|c| c[0] << 4 | c[1]).collect();
        assert_eq!(decoded, id);
    }

    #[test]
    fn exchange_status_byte_is_not_data() {
        let ok = [&b"\xd5\x41\x00"[..], &[0xab; 16], &[0x90, 0x00]].concat();
        assert_eq!(exchange_data(&ok), Ok(&[0xab; 16][..]));
        assert_eq!(
            exchange_data(&unhex("d5 41 14 90 00").unwrap()),
            Err("authentication failed (wrong key)".into())
        );
        assert_eq!(
            pn532_data(&unhex("d5 03 32 01 06 07 90 00").unwrap()),
            Ok(&[0x32, 0x01, 0x06, 0x07][..])
        );
    }

    #[test]
    fn id_renderings_round_trip() {
        let id = [0xab, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(em4100_show(id, IdForm::Dec10), "0016909060");
        assert_eq!(em4100_show(id, IdForm::Dec35), "00200772");
        assert_eq!(em4100_show(id, IdForm::Hex), "ab 01 02 03 04");
        for form in IdForm::ALL {
            let text = em4100_show(id, form);
            assert_eq!(em4100_parse(&text, form, id), Ok(id), "{form:?}");
        }
    }

    #[test]
    fn a_decimal_edit_keeps_the_bytes_it_does_not_describe() {
        let base = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        assert_eq!(
            em4100_parse("0000000001", IdForm::Dec10, base).unwrap(),
            [0xaa, 0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            em4100_parse("00100002", IdForm::Dec35, base).unwrap(),
            [0xaa, 0xbb, 1, 0x00, 0x02]
        );
    }

    #[test]
    fn em4100_parse_rejects_what_it_cannot_represent() {
        let b = [0; 5];
        assert!(em4100_parse("12 34 56", IdForm::Hex, b).is_err(), "short");
        assert!(
            em4100_parse("4294967296", IdForm::Dec10, b).is_err(),
            "over u32"
        );
        assert!(
            em4100_parse("0572129", IdForm::Dec35, b).is_err(),
            "7 digits"
        );
        assert!(
            em4100_parse("25621299", IdForm::Dec35, b).is_err(),
            "256 over u8"
        );
        assert!(
            em4100_parse("00199999", IdForm::Dec35, b).is_err(),
            "99999 over u16"
        );
        assert!(em4100_parse("00165535", IdForm::Dec35, b).is_ok());
    }

    #[test]
    fn every_sector_ends_in_exactly_one_trailer() {
        assert_eq!(*sector_blocks(32).start(), 128);
        assert_eq!(*sector_blocks(39).end(), 255);
        for s in 0..40u8 {
            let blocks: Vec<u8> = sector_blocks(s).collect();
            let (last, rest) = blocks.split_last().unwrap();
            assert!(is_trailer(*last), "sector {s} trailer");
            assert!(rest.iter().all(|b| !is_trailer(*b)), "sector {s} data");
        }
    }
}
