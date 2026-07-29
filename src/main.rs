//! Run with no arguments for the TUI. Anything that changes a tag needs `--yes`.

mod proto;
mod reader;
mod tui;

use clap::{Parser, Subcommand};
use proto::{hex, unhex};
use reader::Reader;
use std::error::Error;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// ms to wait for each reply report.
    #[arg(long, default_value_t = 1000, global = true)]
    timeout: i32,

    /// TUI only. ms of quiet left between polls of an empty pad.
    #[arg(long, default_value_t = tui::IDLE_GAP)]
    poll_gap: u64,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// List matching HID devices without opening them.
    Info,
    /// Send the PN532 GetFirmwareVersion passthrough.
    Probe,
    /// Sound buzzer and flash LED.
    Beep {
        /// Duration in tenths of a second.
        #[arg(long, default_value_t = 5)]
        dur: u8,
    },
    /// Send an arbitrary payload, e.g. `raw "ff 00 80 01 00"`.
    Raw { payload: String },

    /// Read a 125 kHz tag ID, sweeping the vendor's demodulator profiles.
    Read {
        /// Repeat the whole sweep this many times before giving up.
        #[arg(long, default_value_t = 3)]
        tries: u32,
    },
    /// Write a 5-byte ID to a blank T5577 as EM4100. Needs --yes.
    Write {
        /// Five hex bytes, e.g. "12 34 56 78 9a".
        id: String,
        /// Also write block 0, the config word that makes the tag emit at all.
        #[arg(long)]
        config: bool,
        /// Proceed even though a different ID already reads on the pad.
        #[arg(long)]
        overwrite: bool,
        /// Actually write. Without it this only prints the plan.
        #[arg(long)]
        yes: bool,
    },
    /// Write one raw 32-bit block. Needs --yes. For protocol work.
    WriteBlock {
        #[arg(value_parser = hexarg)]
        block: u8,
        /// Four hex bytes.
        data: String,
        #[arg(long)]
        yes: bool,
    },
    /// Dump the 32-bit blocks of a 125 kHz tag. Read-only.
    Blocks {
        /// Highest block number to read. A T5577 has 0 through 7.
        #[arg(long, default_value_t = 7)]
        to: u8,
    },

    /// Send the 0x66 codes the vendor uses but latchkey does not understand, and
    /// report what each answers. Reads the tag ID before and after so a code
    /// that changed the tag is visible.
    ///
    /// Only ever point this at a tag you are willing to destroy. By default it
    /// sends the codes whose argument is too short to carry block data; `--all`
    /// adds the ones that could program the tag.
    LfProbe {
        /// Send one code only, e.g. `--code 12`.
        #[arg(long, value_parser = hexarg)]
        code: Option<u8>,
        /// Also send the codes that take a 4-byte argument and could write.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Identify the 13.56 MHz card on the pad. Read-only. UNVERIFIED: no card
    /// has been available to test the HF path against.
    Hf {
        /// Print the raw detect payload rather than the decoded fields.
        #[arg(long)]
        raw: bool,
    },
    /// Dump MIFARE Classic sectors, trying each key in the dictionary.
    HfDump {
        /// Highest sector to try. Defaults to what the card's SAK implies.
        #[arg(long)]
        to: Option<u8>,
        /// Extra keys to try, as 12 hex digits each.
        #[arg(long, value_delimiter = ',')]
        key: Vec<String>,
        /// Write the dump here as raw 16-byte blocks.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Write one 16-byte MIFARE block. Needs --yes.
    HfWrite {
        block: u8,
        /// Sixteen hex bytes.
        data: String,
        /// Key for the block's sector, 12 hex digits. Tries the dictionary if
        /// not given.
        #[arg(long)]
        key: Option<String>,
        /// Authenticate with key B instead of key A.
        #[arg(long)]
        key_b: bool,
        /// Permit writing a sector trailer, which can lock the sector forever.
        #[arg(long)]
        trailer: bool,
        #[arg(long)]
        yes: bool,
    },

    /// Print what is on the pad whenever it changes.
    ///
    /// The reader detects tags on its own while idle, and only a detected tag
    /// reads back. Polling too hard starves that. If the reader stops beeping
    /// and lighting green when you set a tag down, raise --gap.
    Watch {
        /// Milliseconds of quiet between polls.
        #[arg(long, default_value_t = tui::IDLE_GAP)]
        gap: u64,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
}

/// ASK/Manchester, RF/64, two data blocks, no password. A blank has no valid
/// config and is invisible to the reader until this is written
const T5577_EM4100: [u8; 4] = [0x00, 0x14, 0x80, 0x40];

/// Factory default first, then the published keys
const KEYS: [[u8; 6]; 8] = [
    [0xff; 6],
    [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5],
    [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5],
    [0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7],
    [0x00; 6],
    [0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd],
    [0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a],
    [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
];

fn hexarg(s: &str) -> Result<u8, String> {
    u8::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).map_err(|e| format!("{s:?}: {e}"))
}

fn key_arg(s: &str) -> Result<[u8; 6], String> {
    unhex(s)?
        .try_into()
        .map_err(|v: Vec<u8>| format!("a key is 6 bytes, got {}", v.len()))
}

/// Never retries: a silence is itself the result
fn transact(rd: &mut Reader, payload: &[u8]) -> Result<(), Box<dyn Error>> {
    let frame = proto::encode(payload, 0)?;
    println!("TX payload {}", hex(payload));
    println!("TX frame   {}", hex(&frame[..frame[2] as usize + 1]));

    let reports = rd.raw(payload)?;
    if reports.is_empty() {
        println!("\nno reply within {}ms", rd.timeout);
    }
    for (i, r) in reports.iter().enumerate() {
        println!("RX raw[{i}]  {}", hex(r));
    }
    match reader::decode_reply(&reports) {
        Ok(d) => println!(
            "RX payload {}  seq={} cksum={} trailer={}",
            hex(&d.payload),
            d.seq,
            if d.checksum_ok { "ok" } else { "BAD" },
            if d.trailer_ok { "ok" } else { "BAD" },
        ),
        Err(e) if !reports.is_empty() => println!("RX undecoded: {e}"),
        Err(_) => {}
    }
    Ok(())
}

/// A failed attempt desynchronises the card, so re-select between tries
fn find_key(
    rd: &mut Reader,
    blk: u8,
    uid: &[u8],
    key_b: bool,
    keys: &[[u8; 6]],
) -> Option<[u8; 6]> {
    for k in keys {
        let _ = rd.hf_activate();
        if rd.mifare_auth(key_b, blk, *k, uid).is_ok() {
            return Some(*k);
        }
    }
    None
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let Some(cmd) = cli.cmd else {
        return tui::run(cli.timeout, cli.poll_gap);
    };

    match cmd {
        Cmd::Info => {
            let api = hidapi::HidApi::new()?;
            let mut found = 0;
            for d in api
                .device_list()
                .filter(|d| d.vendor_id() == proto::VID && d.product_id() == proto::PID)
            {
                found += 1;
                println!(
                    "{:04x}:{:04x}  {}  {}  usage_page={:#06x} usage={:#06x}",
                    d.vendor_id(),
                    d.product_id(),
                    d.manufacturer_string().unwrap_or("?"),
                    d.product_string().unwrap_or("?"),
                    d.usage_page(),
                    d.usage(),
                );
            }
            if found == 0 {
                println!("no {:04x}:{:04x} device found", proto::VID, proto::PID);
            }
        }
        Cmd::Probe => {
            let mut rd = Reader::open(cli.timeout)?;
            transact(&mut rd, &proto::pn532(&[0x02]))?;
        }
        Cmd::Beep { dur } => {
            let mut rd = Reader::open(cli.timeout)?;
            println!("{}", hex(&rd.beep(dur)?));
        }
        Cmd::Raw { payload } => {
            let mut rd = Reader::open(cli.timeout)?;
            transact(&mut rd, &unhex(&payload)?)?;
        }

        Cmd::Read { tries } => {
            let mut rd = Reader::open(cli.timeout)?;
            match rd.lf_id_tries(tries) {
                Some((id, freq, lc)) => println!("{freq} Hz  lc {lc:02x}  ID {}", hex(&id)),
                None => println!("No ID in any profile. Is the tag flat on the pad?"),
            }
        }
        Cmd::Write {
            id,
            config,
            overwrite,
            yes,
        } => {
            let id: [u8; 5] = unhex(&id)?
                .try_into()
                .map_err(|v: Vec<u8>| format!("need 5 hex bytes, got {}", v.len()))?;
            let frame = proto::em4100_frame(id).to_be_bytes();
            let (b1, b2) = frame.split_at(4);

            println!("ID     {}", hex(&id));
            println!("frame  {}", hex(&frame));
            if config {
                println!(
                    "block0 {}  T5577 config: ASK/Manchester, RF/64, 2 blocks",
                    hex(&T5577_EM4100)
                );
            }
            println!("block1 {}", hex(b1));
            println!("block2 {}", hex(b2));
            if !yes {
                println!("\nNothing written. Add --yes to go ahead.");
                return Ok(());
            }

            let mut rd = Reader::open(cli.timeout)?;

            // The guard that keeps a working fob working
            match rd.lf_id() {
                Some((cur, ..)) if cur == id => println!("\nAlready reads as {}.", hex(&cur)),
                Some((cur, ..)) if !overwrite => {
                    return Err(format!(
                        "the tag on the pad reads as {}. You asked to write {}.\n\
                         Refusing to overwrite it. Pass --overwrite to go ahead anyway.",
                        hex(&cur),
                        hex(&id)
                    )
                    .into());
                }
                Some((cur, ..)) => println!("\nOverwriting {}.", hex(&cur)),
                None => println!("\nNo ID reads off the pad now."),
            }

            let mut plan: Vec<(u8, [u8; 4])> = Vec::new();
            if config {
                plan.push((0, T5577_EM4100));
            }
            plan.push((1, b1.try_into().unwrap()));
            plan.push((2, b2.try_into().unwrap()));

            for (blk, data) in plan {
                match rd.lf_write_block(blk, data) {
                    Ok(p) => println!("write block {blk} {}  -> {}", hex(&data), hex(&p)),
                    Err(e) => println!("write block {blk} {}  -> {e}", hex(&data)),
                }
            }

            // A write answers `00` whatever happened, so read it back
            println!("\nReading back:");
            match rd.lf_id_tries(3) {
                Some((got, ..)) => println!(
                    "  {}  {}",
                    hex(&got),
                    if got == id {
                        "matches"
                    } else {
                        "DOES NOT MATCH"
                    }
                ),
                None => println!("  no ID read back"),
            }
        }
        Cmd::WriteBlock { block, data, yes } => {
            let data: [u8; 4] = unhex(&data)?
                .try_into()
                .map_err(|v: Vec<u8>| format!("need 4 hex bytes, got {}", v.len()))?;
            let payload = proto::lf_write_block(125_000, block, data);
            if !yes {
                println!("would send {}\n\nAdd --yes to go ahead.", hex(&payload));
                return Ok(());
            }
            let mut rd = Reader::open(cli.timeout)?;
            transact(&mut rd, &payload)?;
        }
        Cmd::Blocks { to } => {
            let mut rd = Reader::open(cli.timeout)?;
            for blk in 0..=to {
                let shown = match rd.lf_read_block(blk) {
                    Ok(p) => hex(&p),
                    Err(e) => e,
                };
                println!("block {blk}  {shown}");
            }
        }

        Cmd::LfProbe { code, all, yes } => {
            // Argument length decides whether a code could carry block data, and
            // so which are safe to send unprompted
            const SHORT: [(u8, usize); 3] = [(0x41, 1), (0x46, 1), (0x12, 4)];
            const WRITEY: [(u8, usize); 11] = [
                (0x01, 5),
                (0x1f, 4),
                (0x21, 4),
                (0x22, 4),
                (0x2f, 4),
                (0x32, 4),
                (0x33, 4),
                (0x34, 4),
                (0x3f, 4),
                (0x42, 4),
                (0x4f, 4),
            ];

            let mut todo: Vec<(u8, usize)> = SHORT.to_vec();
            if all {
                todo.extend_from_slice(&WRITEY);
            }
            if let Some(c) = code {
                todo.retain(|(k, _)| *k == c);
                if todo.is_empty() {
                    todo.push((c, 4));
                }
            }

            println!(
                "codes: {}",
                todo.iter()
                    .map(|(c, _)| format!("{c:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            if !yes {
                println!(
                    "\nNothing sent. This can destroy the tag on the pad. Add --yes\n\
                     once you are sure it is a spare."
                );
                return Ok(());
            }

            let mut rd = Reader::open(cli.timeout)?;
            let before = rd.lf_id();
            match before {
                Some((id, ..)) => println!("tag reads {} before\n", hex(&id)),
                None => println!("no ID reads off the pad before\n"),
            }

            for (c, arglen) in todo {
                let mut p = vec![0xff, 0x00, 0x66, 0x00, 0x1e];
                p.extend_from_slice(&125_000u32.to_le_bytes());
                p.push(c);
                p.extend(std::iter::repeat_n(0, arglen));
                let shown = match rd.send_retry(&p) {
                    Ok(r) => hex(&r.payload),
                    Err(e) => e,
                };
                println!("code {c:02x}  arg {arglen} zero bytes  -> {shown}");
            }

            println!();
            match (before, rd.lf_id()) {
                (Some((a, ..)), Some((b, ..))) if a == b => {
                    println!("tag still reads {}. Nothing here wrote to it.", hex(&a))
                }
                (_, Some((b, ..))) => println!("tag now reads {}  CHANGED", hex(&b)),
                (Some((a, ..)), None) => {
                    println!("tag read {} before and reads nothing now  CHANGED", hex(&a))
                }
                (None, None) => {
                    println!("still no ID. Nothing here made the tag readable.")
                }
            }
        }
        Cmd::Hf { raw } => {
            let mut rd = Reader::open(cli.timeout)?;
            if raw {
                println!("{}", hex(&rd.hf_raw()?));
                return Ok(());
            }
            match rd.hf_card() {
                Some(c) => {
                    println!("UID   {}", hex(&c.uid));
                    println!("ATQA  {}", hex(&c.atqa));
                    println!("SAK   {:02x}", c.sak);
                    println!("type  {}", c.kind());
                    match c.sectors() {
                        Some(n) => println!("      {n} sectors, `hf-dump` can read them"),
                        None => println!("      no MIFARE Classic sectors to dump"),
                    }
                }
                None => println!("no card. Is it flat on the pad?"),
            }
        }
        Cmd::HfDump { to, key, out } => {
            let mut keys: Vec<[u8; 6]> =
                key.iter().map(|s| key_arg(s)).collect::<Result<_, _>>()?;
            keys.extend_from_slice(&KEYS);

            let mut rd = Reader::open(cli.timeout)?;
            let card = rd.hf_card().ok_or("no card on the pad")?;
            println!(
                "UID {}  SAK {:02x}  {}",
                hex(&card.uid),
                card.sak,
                card.kind()
            );

            let sectors = to
                .or_else(|| card.sectors())
                .ok_or("this card has no Classic sectors; pass --to to try anyway")?;
            println!("{sectors} sectors, {} keys\n", keys.len());

            let mut dump: Vec<u8> = Vec::new();
            let mut locked = 0;
            for s in 0..sectors {
                let blocks: Vec<u8> = proto::sector_blocks(s).collect();
                let first = blocks[0];
                let Some(k) = find_key(&mut rd, first, &card.uid, false, &keys) else {
                    println!("sector {s:>2}  no key worked");
                    locked += 1;
                    dump.extend(std::iter::repeat_n(0, blocks.len() * 16));
                    continue;
                };
                println!("sector {s:>2}  key A {}", hex(&k));
                for b in blocks {
                    match rd.mifare_read(b) {
                        Ok(d) => {
                            println!("  {b:>3}  {}", hex(&d));
                            dump.extend_from_slice(&d);
                        }
                        Err(e) => {
                            println!("  {b:>3}  {e}");
                            dump.extend(std::iter::repeat_n(0, 16));
                        }
                    }
                }
            }
            let _ = rd.hf_release();

            if locked > 0 {
                println!("\n{locked} of {sectors} sectors had no key in the dictionary.");
                println!("Their blocks read as zeroes in the output. They were never read.");
            }
            if let Some(path) = out {
                std::fs::write(&path, &dump)?;
                println!("\nwrote {} bytes to {}", dump.len(), path.display());
            }
        }
        Cmd::HfWrite {
            block,
            data,
            key,
            key_b,
            trailer,
            yes,
        } => {
            let data: [u8; 16] = unhex(&data)?
                .try_into()
                .map_err(|v: Vec<u8>| format!("need 16 hex bytes, got {}", v.len()))?;

            if proto::is_trailer(block) && !trailer {
                return Err(format!(
                    "block {block} is a sector trailer. It holds the sector's keys and\n\
                     access bits, and a wrong value locks the sector permanently.\n\
                     Pass --trailer if you really mean it."
                )
                .into());
            }

            println!("block {block}  {}", hex(&data));
            if !yes {
                println!("\nNothing written. Add --yes to go ahead.");
                return Ok(());
            }

            let mut rd = Reader::open(cli.timeout)?;
            let card = rd.hf_card().ok_or("no card on the pad")?;
            println!("UID {}  {}", hex(&card.uid), card.kind());

            let keys = match key {
                Some(s) => vec![key_arg(&s)?],
                None => KEYS.to_vec(),
            };
            let k = find_key(&mut rd, block, &card.uid, key_b, &keys)
                .ok_or("could not authenticate for that block")?;
            println!(
                "authenticated with key {} {}",
                if key_b { "B" } else { "A" },
                hex(&k)
            );

            let before = rd.mifare_read(block);
            if let Ok(b) = &before {
                println!("was    {}", hex(b));
            }
            rd.mifare_write(block, data)?;

            // Re-authenticate, or the read-back fails for reasons unrelated to
            // the write
            find_key(&mut rd, block, &card.uid, key_b, &[k]);
            match rd.mifare_read(block) {
                Ok(got) => println!(
                    "now    {}  {}",
                    hex(&got),
                    if got == data {
                        "matches"
                    } else {
                        "DOES NOT MATCH"
                    }
                ),
                Err(e) => println!("read back failed: {e}"),
            }
            let _ = rd.hf_release();
        }

        Cmd::Watch { gap, seconds } => {
            let mut rd = Reader::open(200)?;
            let start = std::time::Instant::now();
            let deadline = start + std::time::Duration::from_secs(seconds);
            println!("gap {gap}ms. Put a tag down and take it off again.");
            let mut last: Option<[u8; 5]> = None;
            let mut misses = 0;
            while std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(gap));
                let now = rd.lf_id_quick(2);
                misses = if now.is_none() { misses + 1 } else { 0 };
                // One silence is a dropped command more often than a removal
                if now.is_none() && misses < 2 {
                    continue;
                }
                if now != last {
                    let t = start.elapsed().as_secs_f32();
                    match now {
                        Some(id) => println!("{t:6.1}s  {}", hex(&id)),
                        None => println!("{t:6.1}s  clear"),
                    }
                    last = now;
                }
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

