use crate::proto::{self, PID, REPORT, Reply, VID, hex};
use hidapi::{HidApi, HidDevice};
use std::time::{Duration, Instant};

/// Vendor's own gap between LF commands. Shorter and the reader starts
/// ignoring commands after the first successful one.
const PACE: Duration = Duration::from_millis(40);

const TRIES: u32 = 4;

const DRAIN: i32 = 20;

pub struct Reader {
    dev: HidDevice,
    seq: u16,
    /// Every path funnels through `once`, so one gate there paces all of them
    last: Instant,
    /// Set when a command went unanswered. The next reply is then a `00` the
    /// reader owes the abandoned one, not an answer to what was asked
    owed: bool,
    pub timeout: i32,
}

/// A 13.56 MHz card as the detect command describes it.
///
/// Untested. Splitting the detect reply into these three fields is inference,
/// and `kind` uses the published SAK tables rather than the vendor's own branch
/// tree at 0x407031.
#[derive(Clone, Debug, PartialEq)]
pub struct Card {
    pub atqa: [u8; 2],
    pub sak: u8,
    pub uid: Vec<u8>,
}

impl Card {
    pub fn kind(&self) -> &'static str {
        match self.sak {
            0x08 => "MIFARE Classic 1K",
            0x09 => "MIFARE Classic Mini",
            0x18 => "MIFARE Classic 4K",
            0x00 => "MIFARE Ultralight or NTAG",
            0x20 => "ISO 14443-4 (DESFire or JavaCard)",
            0x28 => "SmartMX emulating Classic 1K",
            0x38 => "SmartMX emulating Classic 4K",
            _ => "unknown",
        }
    }

    pub fn sectors(&self) -> Option<u8> {
        match self.sak {
            0x08 | 0x28 => Some(16),
            0x09 => Some(5),
            0x18 | 0x38 => Some(40),
            _ => None,
        }
    }
}

impl Reader {
    pub fn open(timeout: i32) -> Result<Self, String> {
        let api = HidApi::new().map_err(|e| e.to_string())?;
        let dev = api.open(VID, PID).map_err(|e| {
            format!(
                "cannot open {VID:04x}:{PID:04x}: {e}\n\
                 Is the reader plugged in with a data cable?"
            )
        })?;
        Ok(Self {
            dev,
            // Distinct per run, so a reply is identifiable as this run's. Kept
            // even, since the device replies seq + 1
            seq: std::process::id() as u16 & !1,
            last: Instant::now(),
            owed: false,
            timeout,
        })
    }

    /// Send once and collect every reply report. Long replies span reports and
    /// announce the total in the first one's length byte
    fn once(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        // Waiting out the rest of PACE costs nothing when the caller already did
        if let Some(rest) = PACE.checked_sub(self.last.elapsed()) {
            std::thread::sleep(rest);
        }

        let mut buf = [0u8; REPORT];
        // A reply the caller gave up waiting for stays queued, and outlives a
        // close and reopen of the device. Left there it answers this command
        while self.dev.read_timeout(&mut buf, 0).unwrap_or(0) > 0 {}

        self.seq = self.seq.wrapping_add(2);
        let frame = proto::encode(payload, self.seq)?;
        self.dev.write(&frame).map_err(|e| e.to_string())?;

        let want = self.seq.wrapping_add(1);
        let mut out = Vec::new();
        loop {
            let wait = if out.is_empty() { self.timeout } else { DRAIN };
            let n = self
                .dev
                .read_timeout(&mut buf, wait)
                .map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            // The previous command's reply can land after the drain above
            if out.is_empty() && proto::decode(&buf[..n]).is_ok_and(|r| r.seq != want) {
                continue;
            }
            out.push(buf[..n].to_vec());
        }
        self.last = Instant::now();
        self.owed = out.is_empty();
        Ok(out)
    }

    /// Raw reports, no retry.
    pub fn raw(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.once(payload)
    }

    /// One-shot; commands where silence is the expected answer.
    pub fn send(&mut self, payload: &[u8]) -> Result<Reply, String> {
        let owed = self.owed;
        let r = decode_reply(&self.once(payload)?);
        // Spend the `00` the reader owes an abandoned command, then ask again
        if owed && matches!(&r, Ok(d) if d.payload == [0]) {
            return decode_reply(&self.once(payload)?);
        }
        r
    }

    /// Commands that always answer, where silence means the reader dropped it.
    pub fn send_retry(&mut self, payload: &[u8]) -> Result<Reply, String> {
        let mut last = String::from("no reply");
        for _ in 0..TRIES {
            match self.send(payload) {
                Ok(r) => return Ok(r),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn payload(&mut self, p: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.send_retry(p)?.payload)
    }

    // ---- 125 kHz ----

    /// Sweep every demodulator profile. Returns the ID and the profile that
    /// answered.
    pub fn lf_id(&mut self) -> Option<([u8; 5], u32, u8)> {
        for (freq, lc, w1, w2) in proto::LF_PROFILES {
            if let Ok(r) = self.send(&proto::lf_read(freq, lc, w1, w2))
                && let Some(id) = proto::lf_id(&r.payload)
            {
                return Some((id, freq, lc));
            }
        }
        None
    }

    /// A reader that just answered often drops the next few commands, so the
    /// whole sweep is worth repeating.
    pub fn lf_id_tries(&mut self, tries: u32) -> Option<([u8; 5], u32, u8)> {
        (0..tries).find_map(|_| self.lf_id())
    }

    /// The 125 kHz profile only. For polling: the full sweep waits out a timeout
    /// per profile.
    pub fn lf_id_quick(&mut self, tries: u32) -> Option<[u8; 5]> {
        let (freq, lc, w1, w2) = proto::LF_PROFILES[0];
        let p = proto::lf_read(freq, lc, w1, w2);
        for _ in 0..tries {
            // An empty reply is an answer. Only silence is worth asking again
            if let Ok(r) = self.send(&p) {
                return proto::lf_id(&r.payload);
            }
        }
        None
    }

    /// Every profile that answers, not just the first. They are not
    /// tag-exclusive, so more than one usually does.
    pub fn lf_profiles(&mut self) -> Vec<(u32, u8, [u8; 5])> {
        let mut out = Vec::new();
        for (freq, lc, w1, w2) in proto::LF_PROFILES {
            if let Ok(r) = self.send(&proto::lf_read(freq, lc, w1, w2))
                && let Some(id) = proto::lf_id(&r.payload)
            {
                out.push((freq, lc, id));
            }
        }
        out
    }

    /// Zeroes every block. Config word last, so an interrupted wipe leaves the
    /// tag still emitting.
    pub fn lf_wipe(&mut self) -> Vec<(u8, Result<Vec<u8>, String>)> {
        proto::WIPE_ORDER
            .iter()
            .map(|blk| (*blk, self.lf_write_block(*blk, [0; 4])))
            .collect()
    }

    pub fn lf_write_block(&mut self, blk: u8, data: [u8; 4]) -> Result<Vec<u8>, String> {
        self.payload(&proto::lf_write_block(125_000, blk, data))
    }

    pub fn lf_read_block(&mut self, blk: u8) -> Result<Vec<u8>, String> {
        self.payload(&proto::lf_read_block(125_000, blk))
    }

    // ---- 13.56 MHz ----

    /// `None` means nothing on the pad rather than an error. The reply is
    /// accepted only in the shape the vendor's parser at 0x406fa3 requires.
    pub fn hf_card(&mut self) -> Option<Card> {
        Self::parse_card(&self.payload(&proto::hf_detect()).ok()?)
    }

    fn parse_card(payload: &[u8]) -> Option<Card> {
        match payload {
            [0x07, sak, a0, a1, u @ ..] if u.len() >= 4 => Some(Card {
                atqa: [*a0, *a1],
                sak: *sak,
                uid: u[..4].to_vec(),
            }),
            _ => None,
        }
    }

    /// The detect payload exactly as it arrived.
    pub fn hf_raw(&mut self) -> Result<Vec<u8>, String> {
        self.payload(&proto::hf_detect())
    }

    pub fn hf_activate(&mut self) -> Result<Vec<u8>, String> {
        self.payload(&proto::hf_activate())
    }

    pub fn hf_release(&mut self) -> Result<Vec<u8>, String> {
        self.payload(&proto::hf_release())
    }

    pub fn mifare_auth(
        &mut self,
        key_b: bool,
        blk: u8,
        key: [u8; 6],
        uid: &[u8],
    ) -> Result<(), String> {
        let uid: [u8; 4] = uid
            .get(..4)
            .ok_or("need at least four UID bytes to authenticate")?
            .try_into()
            .unwrap();
        let p = self.payload(&proto::mifare_auth(key_b, blk, key, uid))?;
        proto::exchange_data(&p).map(|_| ())
    }

    pub fn mifare_read(&mut self, blk: u8) -> Result<[u8; 16], String> {
        let p = self.payload(&proto::mifare_read(blk))?;
        proto::exchange_data(&p)?
            .get(..16)
            .ok_or_else(|| format!("short block read: {}", hex(&p)))?
            .try_into()
            .map_err(|_| "impossible slice length".to_string())
    }

    pub fn mifare_write(&mut self, blk: u8, data: [u8; 16]) -> Result<(), String> {
        let p = self.payload(&proto::mifare_write(blk, data))?;
        proto::exchange_data(&p).map(|_| ())
    }

    pub fn beep(&mut self, dur: u8, reps: u8) -> Result<Vec<u8>, String> {
        self.payload(&proto::beep(dur, reps))
    }

    /// 40 bytes of raw demodulator output. An empty pad reads nearly all ones.
    pub fn lf_samples(&mut self) -> Result<Vec<u8>, String> {
        self.payload(&proto::lf_sample(0x41, 0x05))?;
        let p = self.payload(&proto::lf_sample(0x46, 0x00))?;
        // Length byte then that many bytes, the same shape as the ID read
        match p.split_first() {
            Some((n, rest)) if rest.len() >= *n as usize => Ok(rest[..*n as usize].to_vec()),
            _ => Err(format!("sampler answered {}", hex(&p))),
        }
    }

    /// Model and serial. `wCopy NSR109-HIDIC V806N` and `T37350466633` here.
    pub fn ident(&mut self) -> Result<(String, String), String> {
        let text = |p: Vec<u8>| String::from_utf8_lossy(&p).trim().to_string();
        Ok((
            text(self.payload(&proto::MODEL)?),
            text(self.payload(&proto::SERIAL)?),
        ))
    }
}

/// Decode the first frame, falling back to the concatenation of every report
/// when the length byte announces more than one holds. `p1 = 0x67` does that.
pub fn decode_reply(reports: &[Vec<u8>]) -> Result<Reply, String> {
    let first = reports.first().ok_or("no reply")?;
    match proto::decode(first) {
        Ok(d) => Ok(d),
        Err(_) if reports.len() > 1 => proto::decode(&reports.concat()),
        Err(e) => Err(e),
    }
}
