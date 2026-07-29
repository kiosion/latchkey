use crate::proto::{self, IdForm, hex};
use crate::reader::{Card, Reader};
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use std::error::Error;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

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

/// ASK/Manchester, RF/64, two data blocks, no password
const T5577_EM4100: [u8; 4] = [0x00, 0x14, 0x80, 0x40];

const LAST_BLOCK: u8 = 7;

/// Quiet the reader gets between polls, for its own detection to run. Erring
/// long is the safe direction
pub const IDLE_GAP: u64 = 1500;

const POLL_TRIES: u32 = 2;

/// A stale tag for three seconds costs nothing; flickering costs a lot
const EMPTY_HOLD: Duration = Duration::from_millis(3000);

/// One command per poll is the budget, so HF gets every fourth
const HF_EVERY: u64 = 4;

/// ASCII only, which keeps the cursor a plain byte index
#[derive(Default, Clone)]
struct Input {
    value: String,
    cursor: usize,
}

impl Input {
    fn set(&mut self, s: impl Into<String>) {
        self.value = s.into();
        self.cursor = self.value.len();
    }

    fn key(&mut self, k: KeyCode) {
        match k {
            KeyCode::Char(c) if c.is_ascii_graphic() || c == ' ' => {
                self.value.insert(self.cursor, c);
                self.cursor += 1;
            }
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                self.value.remove(self.cursor);
            }
            KeyCode::Delete if self.cursor < self.value.len() => {
                self.value.remove(self.cursor);
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.value.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.value.len(),
            _ => {}
        }
    }

    /// Block cursor drawn in, so no terminal cursor is needed
    fn spans(&self, active: bool) -> Vec<Span<'static>> {
        if !active {
            return vec![Span::from(self.value.clone())];
        }
        let (before, after) = self.value.split_at(self.cursor);
        let (at, rest) = match after.char_indices().nth(1) {
            Some((i, _)) => after.split_at(i),
            None if after.is_empty() => (" ", ""),
            None => (after, ""),
        };
        vec![
            Span::from(before.to_string()),
            Span::styled(
                at.to_string(),
                Style::new().fg(Color::Black).bg(Color::Yellow),
            ),
            Span::from(rest.to_string()),
        ]
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Pad {
    Empty,
    Lf { id: [u8; 5], freq: u32 },
    Hf(Card),
}

enum Job {
    /// bool asks for a 13.56 MHz check too
    Poll(bool),
    /// Full profile sweep, unlike the poll's single profile
    ReadLf,
    WriteLf([u8; 5], bool),
    ReadBlocks,
    WriteBlock(u8, [u8; 4]),
    Dump,
    Raw(Vec<u8>),
    Beep,
    Quit,
}

/// No key means the blocks were never read, not that they read as zero
type Sector = (u8, Option<[u8; 6]>, Vec<[u8; 16]>);

enum Event {
    Pad(Pad),
    Log(String, bool),
    Busy(&'static str),
    Idle,
    Sector(Sector),
    Block(u8, Result<Vec<u8>, String>),
}

fn worker(mut rd: Reader, jobs: Receiver<Job>, tx: Sender<Event>) {
    let say = |m: String, bad: bool| {
        let _ = tx.send(Event::Log(m, bad));
    };
    // A poll waits out its timeout on an empty pad, so it gets a short one
    let full = rd.timeout;
    const POLL_TIMEOUT: i32 = 200;

    while let Ok(job) = jobs.recv() {
        rd.timeout = if matches!(job, Job::Poll(_)) {
            POLL_TIMEOUT
        } else {
            full
        };
        let busy = match &job {
            Job::ReadLf => Some("reading"),
            Job::WriteLf(..) | Job::WriteBlock(..) => Some("writing"),
            Job::ReadBlocks => Some("reading blocks"),
            Job::Dump => Some("dumping"),
            Job::Raw(_) => Some("sending"),
            Job::Beep => Some("beeping"),
            _ => None,
        };
        if let Some(b) = busy {
            let _ = tx.send(Event::Busy(b));
        }

        match job {
            Job::Quit => return,
            Job::Poll(check_hf) => {
                let pad = match rd.lf_id_quick(POLL_TRIES) {
                    Some(id) => Pad::Lf { id, freq: 125_000 },
                    None if check_hf => match rd.hf_card() {
                        Some(c) => Pad::Hf(c),
                        None => Pad::Empty,
                    },
                    None => Pad::Empty,
                };
                if tx.send(Event::Pad(pad)).is_err() {
                    return;
                }
                continue;
            }
            Job::ReadLf => {
                match rd.lf_id_tries(2) {
                    Some((id, freq, lc)) => {
                        say(format!("{freq} Hz lc {lc:02x}  {}", hex(&id)), false);
                        let _ = tx.send(Event::Pad(Pad::Lf { id, freq }));
                    }
                    None => say("no ID in any profile".into(), true),
                };
            }
            Job::Beep => {
                match rd.beep(5) {
                    Ok(_) => say("beep".into(), false),
                    Err(e) => say(e, true),
                };
            }
            Job::Raw(p) => {
                say(format!("-> {}", hex(&p)), false);
                match rd.send_retry(&p) {
                    Ok(r) => {
                        let mut note = String::new();
                        if !r.checksum_ok {
                            note.push_str("  [cksum BAD]");
                        }
                        if !r.trailer_ok {
                            note.push_str("  [trailer BAD]");
                        }
                        say(format!("<- {}{note}", hex(&r.payload)), !note.is_empty());
                    }
                    Err(e) => say(format!("<- {e}"), true),
                };
            }
            Job::WriteBlock(blk, data) => {
                match rd.lf_write_block(blk, data) {
                    Ok(p) => say(
                        format!("block {blk} <- {}  reply {}", hex(&data), hex(&p)),
                        false,
                    ),
                    Err(e) => say(format!("block {blk}: {e}"), true),
                };
                // The reply says nothing about success, so read it back
                let got = rd.lf_read_block(blk);
                let _ = tx.send(Event::Block(blk, got));
            }
            Job::ReadBlocks => {
                for blk in 0..=LAST_BLOCK {
                    let got = rd.lf_read_block(blk);
                    if tx.send(Event::Block(blk, got)).is_err() {
                        return;
                    }
                }
            }
            Job::WriteLf(id, config) => {
                let frame = proto::em4100_frame(id).to_be_bytes();
                let (b1, b2) = frame.split_at(4);
                let mut plan = Vec::new();
                if config {
                    plan.push((0u8, T5577_EM4100));
                }
                plan.push((1, b1.try_into().unwrap()));
                plan.push((2, b2.try_into().unwrap()));

                let mut failed = false;
                for (blk, data) in plan {
                    if let Err(e) = rd.lf_write_block(blk, data) {
                        say(format!("block {blk}: {e}"), true);
                        failed = true;
                    }
                }
                // A write answers `00` whatever happened, so read it back
                if !failed {
                    match rd.lf_id_tries(3) {
                        Some((got, freq, _)) if got == id => {
                            say(format!("wrote {} and read it back", hex(&id)), false);
                            let _ = tx.send(Event::Pad(Pad::Lf { id: got, freq }));
                        }
                        Some((got, freq, _)) => {
                            say(
                                format!("wrote {} but tag reads {}", hex(&id), hex(&got)),
                                true,
                            );
                            let _ = tx.send(Event::Pad(Pad::Lf { id: got, freq }));
                        }
                        None => say("wrote, but nothing reads back. Try block 0.".into(), true),
                    }
                }
            }
            Job::Dump => {
                let Some(card) = rd.hf_card() else {
                    say("no card on the pad".into(), true);
                    let _ = tx.send(Event::Idle);
                    continue;
                };
                let Some(sectors) = card.sectors() else {
                    say(format!("{} has no Classic sectors", card.kind()), true);
                    let _ = tx.send(Event::Idle);
                    continue;
                };
                for s in 0..sectors {
                    let blocks: Vec<u8> = proto::sector_blocks(s).collect();
                    let mut found = None;
                    for k in KEYS {
                        let _ = rd.hf_activate();
                        if rd.mifare_auth(false, blocks[0], k, &card.uid).is_ok() {
                            found = Some(k);
                            break;
                        }
                    }
                    let data = match found {
                        None => Vec::new(),
                        Some(_) => blocks
                            .iter()
                            .map(|b| rd.mifare_read(*b).unwrap_or([0; 16]))
                            .collect(),
                    };
                    if tx.send(Event::Sector((s, found, data))).is_err() {
                        return;
                    }
                }
                let _ = rd.hf_release();
                say(format!("dumped {sectors} sectors"), false);
            }
        }
        let _ = tx.send(Event::Idle);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Screen {
    Tag,
    Card,
    Blocks,
    Console,
}

impl Screen {
    const ALL: [Screen; 4] = [Screen::Tag, Screen::Card, Screen::Blocks, Screen::Console];

    fn tab(self) -> &'static str {
        match self {
            Self::Tag => "1 Tag",
            Self::Card => "2 Card",
            Self::Blocks => "3 Blocks",
            Self::Console => "4 Console",
        }
    }

    fn keys(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Tag => &[
                ("up/down", "form"),
                ("e", "edit"),
                ("c", "capture"),
                ("r", "read"),
                ("0", "block 0"),
                ("w", "write"),
            ],
            Self::Card => &[("d", "dump"), ("s", "save")],
            Self::Blocks => &[
                ("up/down", "block"),
                ("e", "edit"),
                ("r", "read all"),
                ("w", "write"),
            ],
            Self::Console => &[("e", "edit"), ("Enter", "send")],
        }
    }

    fn step(self, back: bool) -> Self {
        let i = Self::ALL.iter().position(|s| *s == self).unwrap();
        let n = Self::ALL.len();
        Self::ALL[if back { (i + n - 1) % n } else { (i + 1) % n }]
    }
}

/// Only `Blank` is safe to overwrite from the pad
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    Blank,
    Captured,
    Typed,
}

impl Origin {
    fn label(self) -> &'static str {
        match self {
            Self::Blank => "empty",
            Self::Captured => "captured",
            Self::Typed => "typed",
        }
    }
}

struct Confirm {
    prompt: Vec<String>,
    job: Job,
}

struct App {
    screen: Screen,
    pad: Pad,
    /// Drives the heartbeat; frozen means a reader that stopped answering
    polls: u64,
    log: Vec<(String, bool)>,
    busy: Option<&'static str>,
    confirm: Option<Confirm>,
    help: bool,
    jobs: Sender<Job>,

    /// The ID a write would use, independent of the pad
    id: [u8; 5],
    origin: Origin,
    form: IdForm,
    field: Input,
    field_err: Option<String>,
    write_config: bool,

    blocks: [Option<Result<Vec<u8>, String>>; 8],
    block_sel: u8,
    block_field: Input,

    dump: Vec<Sector>,
    console: Input,

    editing: bool,
    /// State as editing began, for Esc to restore
    snap: Option<(String, [u8; 5], Origin)>,
}

impl App {
    fn new(jobs: Sender<Job>) -> Self {
        let mut a = Self {
            screen: Screen::Tag,
            pad: Pad::Empty,
            polls: 0,
            log: Vec::new(),
            busy: None,
            confirm: None,
            help: false,
            jobs,
            id: [0; 5],
            origin: Origin::Blank,
            form: IdForm::Hex,
            field: Input::default(),
            field_err: None,
            write_config: true,
            blocks: Default::default(),
            block_sel: 0,
            block_field: Input::default(),
            dump: Vec::new(),
            console: Input::default(),
            editing: false,
            snap: None,
        };
        a.sync_field();
        a.block_field.set("00 00 00 00");
        a.console.set("ff 00 00 00 02 d4 02");
        a.log("? for keys", false);
        a
    }

    fn log(&mut self, m: impl Into<String>, bad: bool) {
        self.log.push((m.into(), bad));
        if self.log.len() > 300 {
            self.log.drain(..150);
        }
    }

    fn sync_field(&mut self) {
        self.field.set(proto::em4100_show(self.id, self.form));
        self.field_err = None;
    }

    /// Text that won't parse leaves `id` alone, so a half-typed value is never
    /// what gets written
    fn reparse(&mut self) {
        match proto::em4100_parse(&self.field.value, self.form, self.id) {
            Ok(id) => {
                self.id = id;
                self.field_err = None;
            }
            Err(e) => self.field_err = Some(e),
        }
    }

    /// The only thing that overwrites a captured or typed buffer
    fn capture(&mut self) {
        match self.pad.clone() {
            Pad::Lf { id, .. } => {
                self.id = id;
                self.origin = Origin::Captured;
                self.sync_field();
                self.log(format!("captured {}", hex(&id)), false);
            }
            Pad::Hf(c) => self.log(
                format!("{} is a card UID. This screen takes IDs.", hex(&c.uid)),
                true,
            ),
            Pad::Empty => self.log("nothing on the pad", true),
        }
    }

    fn next_step(&self) -> &'static str {
        match (&self.pad, self.origin) {
            (Pad::Hf(_), _) => "13.56 MHz card. Screen 2 reads those.",
            (Pad::Empty, Origin::Blank) => "set the tag you want to copy on the pad",
            (Pad::Empty, _) => "set a blank down. w writes.",
            (Pad::Lf { .. }, Origin::Blank) => "c captures this tag",
            (Pad::Lf { id, .. }, _) if *id == self.id => "the tag matches the buffer",
            (Pad::Lf { .. }, _) => "w overwrites this tag with the buffer",
        }
    }

    /// Fills an untouched buffer once. After that only `c` replaces it
    fn seed(&mut self, id: [u8; 5]) {
        if self.origin == Origin::Blank && !self.editing {
            self.id = id;
            self.origin = Origin::Captured;
            self.sync_field();
        }
    }

    fn begin_edit(&mut self) {
        if self.screen == Screen::Card {
            return;
        }
        self.snap = Some((self.field_ref().value.clone(), self.id, self.origin));
        self.editing = true;
    }

    fn end_edit(&mut self, revert: bool) {
        if let Some((text, id, origin)) = self.snap.take()
            && revert
        {
            self.id = id;
            self.origin = origin;
            self.field_mut().set(text);
            self.field_err = None;
        }
        self.editing = false;
    }

    fn field_ref(&self) -> &Input {
        match self.screen {
            Screen::Blocks => &self.block_field,
            Screen::Console => &self.console,
            _ => &self.field,
        }
    }

    fn field_mut(&mut self) -> &mut Input {
        match self.screen {
            Screen::Blocks => &mut self.block_field,
            Screen::Console => &mut self.console,
            _ => &mut self.field,
        }
    }

    fn stage_write_lf(&mut self) {
        if let Some(e) = &self.field_err {
            let e = e.clone();
            self.log(format!("fix the ID first: {e}"), true);
            return;
        }
        let id = self.id;
        let mut prompt = vec![format!("Write {} to the tag on the pad?", hex(&id))];
        match &self.pad {
            Pad::Empty => prompt
                .push("Nothing reads on the pad. Normal for a blank, which is silent until block 0 is set.".into()),
            Pad::Lf { id: cur, .. } if *cur == id => {
                prompt.push(format!("It already reads as {}.", hex(cur)))
            }
            Pad::Lf { id: cur, .. } => prompt.push(format!(
                "WARNING: the tag reads as {}. That will be erased. Stop if you cannot replace it.",
                hex(cur)
            )),
            Pad::Hf(c) => prompt.push(format!(
                "A {} is on the pad. A 125 kHz write will not touch it.",
                c.kind()
            )),
        }
        if self.write_config {
            prompt.push(format!("Block 0 will be set to {}.", hex(&T5577_EM4100)));
        }
        prompt.push("y to go ahead. Any other key cancels.".into());
        self.confirm = Some(Confirm {
            prompt,
            job: Job::WriteLf(id, self.write_config),
        });
    }

    fn stage_write_block(&mut self) {
        let data = match proto::unhex(&self.block_field.value) {
            Ok(v) if v.len() == 4 => <[u8; 4]>::try_from(v).unwrap(),
            Ok(v) => {
                self.log(format!("a block is 4 bytes, got {}", v.len()), true);
                return;
            }
            Err(e) => {
                self.log(e, true);
                return;
            }
        };
        let blk = self.block_sel;
        let mut prompt = vec![format!("Write {} to block {blk}?", hex(&data))];
        if blk == 0 {
            prompt.push(
                "Block 0 is the config word. A wrong value stops the tag emitting at all.".into(),
            );
        }
        if let Pad::Lf { id, .. } = &self.pad {
            prompt.push(format!(
                "The tag reads as {}. Blocks 1 and 2 change that.",
                hex(id)
            ));
        }
        prompt.push("y to go ahead. Any other key cancels.".into());
        self.confirm = Some(Confirm {
            prompt,
            job: Job::WriteBlock(blk, data),
        });
    }

    fn send_console(&mut self) {
        match proto::unhex(&self.console.value) {
            Ok(p) if p.is_empty() => self.log("nothing to send", true),
            Ok(p) => {
                let _ = self.jobs.send(Job::Raw(p));
            }
            Err(e) => self.log(e, true),
        }
    }

    fn save_dump(&mut self) {
        if self.dump.is_empty() {
            self.log("no dump to save", true);
            return;
        }
        let uid = match &self.pad {
            Pad::Hf(c) => hex(&c.uid).replace(' ', ""),
            _ => "card".into(),
        };
        let path = format!("{uid}.dump");
        let bytes: Vec<u8> = self
            .dump
            .iter()
            .flat_map(|(s, _, blocks)| {
                // Zero-fill a sector with no key, so block numbering in the file
                // still lines up with the card
                let want = proto::sector_blocks(*s).count();
                let mut v: Vec<u8> = blocks.iter().flatten().copied().collect();
                v.resize(want * 16, 0);
                v
            })
            .collect();
        match std::fs::write(&path, &bytes) {
            Ok(()) => self.log(format!("wrote {} bytes to {path}", bytes.len()), false),
            Err(e) => self.log(format!("{path}: {e}"), true),
        }
    }

    /// False to quit
    fn key(&mut self, k: KeyCode) -> bool {
        // Both swallow the keypress, so `y` never doubles as a shortcut
        if self.help {
            self.help = false;
            return true;
        }
        if let Some(c) = self.confirm.take() {
            if k == KeyCode::Char('y') {
                let _ = self.jobs.send(c.job);
            } else {
                self.log("cancelled", false);
            }
            return true;
        }
        if self.editing {
            return self.key_editing(k);
        }

        match k {
            KeyCode::Char('q') => return false,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Right | KeyCode::Tab => self.screen = self.screen.step(false),
            KeyCode::Left | KeyCode::BackTab => self.screen = self.screen.step(true),
            KeyCode::Char('1') => self.screen = Screen::Tag,
            KeyCode::Char('2') => self.screen = Screen::Card,
            KeyCode::Char('3') => self.screen = Screen::Blocks,
            KeyCode::Char('4') => self.screen = Screen::Console,
            KeyCode::Char('b') => {
                let _ = self.jobs.send(Job::Beep);
            }
            KeyCode::Char('e') => self.begin_edit(),
            _ => self.key_screen(k),
        }
        true
    }

    /// The field takes everything except the two keys that leave it, or typing
    /// "w" into a hex field would start a write
    fn key_editing(&mut self, k: KeyCode) -> bool {
        match k {
            KeyCode::Esc => self.end_edit(true),
            KeyCode::Enter if self.screen == Screen::Console => {
                self.end_edit(false);
                self.send_console();
            }
            KeyCode::Enter => self.end_edit(false),
            _ => match self.screen {
                Screen::Tag => {
                    self.field.key(k);
                    self.origin = Origin::Typed;
                    self.reparse();
                }
                Screen::Blocks => self.block_field.key(k),
                Screen::Console => self.console.key(k),
                Screen::Card => {}
            },
        }
        true
    }

    fn key_screen(&mut self, k: KeyCode) {
        let up = matches!(k, KeyCode::Up | KeyCode::Char('k'));
        let down = matches!(k, KeyCode::Down | KeyCode::Char('j'));
        match self.screen {
            Screen::Tag => match k {
                _ if up || down => {
                    let i = IdForm::ALL.iter().position(|f| *f == self.form).unwrap();
                    let n = IdForm::ALL.len();
                    self.form = IdForm::ALL[if up { (i + n - 1) % n } else { (i + 1) % n }];
                    self.sync_field();
                }
                KeyCode::Char('r') => {
                    let _ = self.jobs.send(Job::ReadLf);
                }
                KeyCode::Char('c') => self.capture(),
                KeyCode::Char('w') => self.stage_write_lf(),
                KeyCode::Char('0') => {
                    self.write_config = !self.write_config;
                    let on = self.write_config;
                    self.log(format!("block 0 {}", if on { "on" } else { "off" }), false);
                }
                _ => {}
            },
            Screen::Card => match k {
                KeyCode::Char('d') => {
                    self.dump.clear();
                    let _ = self.jobs.send(Job::Dump);
                }
                KeyCode::Char('s') => self.save_dump(),
                _ => {}
            },
            Screen::Blocks => match k {
                _ if down => self.block_sel = (self.block_sel + 1).min(LAST_BLOCK),
                _ if up => self.block_sel = self.block_sel.saturating_sub(1),
                KeyCode::Char('r') => {
                    let _ = self.jobs.send(Job::ReadBlocks);
                }
                KeyCode::Char('w') => self.stage_write_block(),
                _ => {}
            },
            Screen::Console => {
                if k == KeyCode::Enter {
                    self.send_console();
                }
            }
        }
    }
}

fn panel(title: &str) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::DarkGray))
        .title(Span::from(format!(" {title} ")).bold())
}

/// `label  value`, label dimmed to a fixed width so columns line up
fn row(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::from(format!(" {label:<11}")).dark_gray(),
        Span::from(value.into()),
    ])
}

fn note(text: &str) -> Line<'static> {
    Line::from(format!(" {text}")).dark_gray()
}

/// Four-byte groups, so a 16-byte block fits the panel
fn hex_groups(bytes: &[u8]) -> String {
    bytes
        .chunks(4)
        .map(|c| c.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn draw_pad(f: &mut Frame, app: &App, area: Rect) {
    let lines = match &app.pad {
        Pad::Empty => vec![
            Line::from(" empty").dark_gray(),
            note("set a tag down flat"),
        ],
        Pad::Lf { id, freq } => vec![
            Line::from(vec![
                Span::from(" 125 kHz   ").dark_gray(),
                Span::styled(hex(id), Style::new().fg(Color::Green).bold()),
                Span::from(format!("   {freq} Hz")).dark_gray(),
            ]),
            Line::from(vec![
                Span::from(" EM4100    ").dark_gray(),
                Span::from(format!(
                    "dec10 {}    dec3+5 {}",
                    proto::em4100_show(*id, IdForm::Dec10),
                    proto::em4100_show(*id, IdForm::Dec35)
                )),
            ]),
        ],
        Pad::Hf(c) => vec![
            Line::from(vec![
                Span::from(" 13.56 MHz ").dark_gray(),
                Span::styled(hex(&c.uid), Style::new().fg(Color::Cyan).bold()),
                Span::from(format!("   {}", c.kind())),
            ]),
            Line::from(vec![
                Span::from(" untested  ").yellow(),
                Span::from(format!(
                    "ATQA {}  SAK {:02x}  {}",
                    hex(&c.atqa),
                    c.sak,
                    match c.sectors() {
                        Some(n) => format!("{n} sectors"),
                        None => "no sectors".into(),
                    }
                ))
                .dark_gray(),
            ]),
        ],
    };
    f.render_widget(Paragraph::new(lines).block(panel("Pad")), area);
}

fn draw_tag(f: &mut Frame, app: &App, area: Rect) {
    let [ids, enc] = Layout::vertical([Constraint::Length(7), Constraint::Min(0)]).areas(area);

    let mut lines = Vec::new();
    for form in IdForm::ALL {
        let here = form == app.form;
        let label = Span::from(format!(
            " {} {:<7}",
            if here { '>' } else { ' ' },
            form.label()
        ));
        let value = if here && app.editing {
            app.field.spans(true)
        } else {
            vec![Span::from(proto::em4100_show(app.id, form))]
        };
        let mut spans = vec![if here {
            label.yellow()
        } else {
            label.dark_gray()
        }];
        spans.extend(value);
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(match &app.field_err {
        Some(e) => Line::from(format!(" {e}")).red(),
        None if app.editing => note(app.form.covers()),
        // Undimmed, since this is guidance rather than a label
        None => Line::from(format!(" {}", app.next_step())).fg(Color::Cyan),
    });

    // Which tag a write would burn must not be ambiguous
    let title = format!("Buffer ({})", app.origin.label());
    f.render_widget(
        Paragraph::new(lines).block(panel(if app.editing {
            "Buffer (editing)"
        } else {
            &title
        })),
        ids,
    );

    let frame = proto::em4100_frame(app.id).to_be_bytes();
    let enc_row = |label: &str, value: String| {
        Line::from(vec![
            Span::from(format!(" {label:<8}")).dark_gray(),
            Span::from(value),
        ])
    };
    let lines = vec![
        enc_row("frame", hex(&frame)),
        Line::from(""),
        enc_row(
            "block 0",
            match app.write_config {
                true => hex(&T5577_EM4100),
                false => "skipped".into(),
            },
        ),
        enc_row("block 1", hex(&frame[..4])),
        enc_row("block 2", hex(&frame[4..])),
    ];
    f.render_widget(Paragraph::new(lines).block(panel("Encodes to")), enc);
}

fn draw_blocks(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    for b in 0..=LAST_BLOCK {
        let here = b == app.block_sel;
        let label = Span::from(format!(" {} block {b}  ", if here { '>' } else { ' ' }));
        let mut spans = vec![if here {
            label.yellow()
        } else {
            label.dark_gray()
        }];
        if here && app.editing {
            spans.extend(app.block_field.spans(true));
        } else {
            // Padded so the notes line up
            spans.push(match &app.blocks[b as usize] {
                None => Span::from(format!("{:<13}", "-")).dark_gray(),
                Some(Ok(p)) => Span::from(format!("{:<13}", hex(p))),
                Some(Err(e)) => Span::from(format!("{:<13}", e.clone())).red(),
            });
        }
        spans.push(
            Span::from(match b {
                0 => "config",
                1 | 2 => "EM4100 data",
                7 => "password",
                _ => "",
            })
            .dark_gray(),
        );
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines).block(panel("T5577 page 0")), area);
}

fn draw_card(f: &mut Frame, app: &App, area: Rect) {
    if app.dump.is_empty() {
        let lines = vec![
            Line::from(match &app.pad {
                Pad::Hf(c) => format!(" {}", c.kind()),
                _ => " no card".into(),
            }),
            Line::from(""),
            row("d", "dump every sector"),
            row("s", "save to <uid>.dump"),
            Line::from(""),
            note(&format!(
                "{} keys tried per sector. Unknown keys",
                KEYS.len()
            )),
            note("are not recovered; those sectors read locked."),
            Line::from(""),
            Line::from(" Untested. No card has ever answered this.").yellow(),
        ];
        f.render_widget(Paragraph::new(lines).block(panel("MIFARE Classic")), area);
        return;
    }

    let mut lines = Vec::new();
    for (s, key, blocks) in &app.dump {
        lines.push(match key {
            Some(k) => Line::from(format!(" sector {s:>2}  key A {}", hex(k))).bold(),
            None => Line::from(format!(" sector {s:>2}  locked")).red(),
        });
        for (i, b) in blocks.iter().enumerate() {
            lines.push(Line::from(format!("   {i:>2}  {}", hex_groups(b))).dark_gray());
        }
    }
    // Nothing scrolls here, so pin the view to the newest sector
    let rows = area.height.saturating_sub(2) as usize;
    let scroll = lines.len().saturating_sub(rows) as u16;
    f.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .block(panel("Dump")),
        area,
    );
}

fn draw_console(f: &mut Frame, app: &App, area: Rect) {
    let [field, examples] =
        Layout::vertical([Constraint::Length(4), Constraint::Min(0)]).areas(area);

    let mut payload = vec![Span::from(" ")];
    payload.extend(app.console.spans(app.editing));
    let lines = vec![
        Line::from(payload),
        note("length, sequence and checksum are added"),
    ];
    f.render_widget(
        Paragraph::new(lines).block(panel(if app.editing {
            "Payload (editing)"
        } else {
            "Payload"
        })),
        field,
    );

    // Two lines per example keeps each payload on one line and copyable
    const EXAMPLES: [(&str, &str); 5] = [
        ("firmware version", "ff 00 00 00 02 d4 02"),
        ("13.56 MHz detect", "ff 00 6a 01 00 08"),
        ("buzzer and LED", "ff 00 40 50 04 01 05 01 01"),
        ("reader config", "ff 00 82 00 00"),
        ("125 kHz ID read", "ff 00 65 08 18 48 e8 01 00 00 00 00 00"),
    ];
    let mut lines = Vec::new();
    for (what, bytes) in EXAMPLES {
        lines.push(note(what));
        lines.push(Line::from(format!("   {bytes}")));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(" Some subcommands wedge the reader until").yellow());
    lines.push(Line::from(" it is replugged. See PROTOCOL.md.").yellow());
    f.render_widget(Paragraph::new(lines).block(panel("Examples")), examples);
}

fn draw_help(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![
        row("left/right", "screen"),
        row("1-4", "jump to screen"),
        row("up/down", "move within screen"),
        row("e", "edit"),
        row("Enter", "accept"),
        row("Esc", "abandon edit"),
        row("b", "buzzer"),
        row("q", "quit"),
        Line::from(""),
        Line::from(format!(" {}", app.screen.tab())).bold(),
    ];
    lines.extend(app.screen.keys().iter().map(|(k, what)| row(k, *what)));
    lines.push(Line::from(""));
    lines.push(note("Writes ask first. Only y goes ahead."));

    let area = center(area, 46, lines.len() as u16 + 2);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::new()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(Color::Yellow))
                .title(Span::from(" Keys ").bold()),
        ),
        area,
    );
}

fn center(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

/// Advances once per poll; frozen means the reader stopped answering
const HEARTBEAT: [char; 4] = ['.', 'o', 'O', 'o'];

fn draw(f: &mut Frame, app: &App) {
    let [tabs, pad, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(4),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(f.area());

    let mut spans = vec![Span::from(" latchkey ").fg(Color::Black).bg(Color::White)];
    for s in Screen::ALL {
        spans.push(if s == app.screen {
            Span::styled(
                format!(" {} ", s.tab()),
                Style::new().fg(Color::Black).bg(Color::Yellow),
            )
        } else {
            Span::from(format!(" {} ", s.tab())).dark_gray()
        });
    }
    spans.push(match app.busy {
        Some(w) => Span::from(format!("  {w}...")).fg(Color::Cyan),
        None => Span::from(format!(
            "  {}",
            HEARTBEAT[(app.polls % HEARTBEAT.len() as u64) as usize]
        ))
        .dark_gray(),
    });
    f.render_widget(Paragraph::new(Line::from(spans)), tabs);

    draw_pad(f, app, pad);

    let [main, side] =
        Layout::horizontal([Constraint::Percentage(52), Constraint::Min(0)]).areas(body);
    match app.screen {
        Screen::Tag => draw_tag(f, app, main),
        Screen::Card => draw_card(f, app, main),
        Screen::Blocks => draw_blocks(f, app, main),
        Screen::Console => draw_console(f, app, main),
    }

    if let Some(c) = &app.confirm {
        let lines: Vec<Line> = c
            .prompt
            .iter()
            .map(|l| Line::from(format!(" {l}")))
            .collect();
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .style(Style::new().fg(Color::Yellow))
                .block(
                    Block::new()
                        .borders(Borders::ALL)
                        .border_style(Style::new().fg(Color::Yellow))
                        .title(Span::from(" Confirm ").bold()),
                ),
            side,
        );
    } else {
        let lines: Vec<Line> = app
            .log
            .iter()
            .rev()
            .map(|(m, bad)| {
                let s = format!(" {m}");
                if *bad {
                    Line::from(s).red()
                } else {
                    Line::from(s)
                }
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(panel("Activity")),
            side,
        );
    }

    let hint = if app.confirm.is_some() {
        " y  go ahead      any other key  cancel".to_string()
    } else if app.editing {
        " Enter  accept    Esc  revert".to_string()
    } else {
        let mut s = String::from(" ");
        for (k, what) in app.screen.keys() {
            s.push_str(&format!("{k} {what}   "));
        }
        s.push_str("? help   q quit");
        s
    };
    f.render_widget(Paragraph::new(hint).dark_gray(), foot);

    if app.help {
        draw_help(f, app, body);
    }
}

pub fn run(timeout: i32, idle_gap: u64) -> Result<(), Box<dyn Error>> {
    // Terminal setup panics on a pipe, which reads as a crash
    if !std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        return Err("no terminal on stdout. Run `latchkey --help` for the subcommands.".into());
    }
    let rd = Reader::open(timeout)?;
    let (jobs_tx, jobs_rx) = channel();
    let (ev_tx, ev_rx) = channel();
    let handle = std::thread::spawn(move || worker(rd, jobs_rx, ev_tx));

    let mut app = App::new(jobs_tx);

    // One poll outstanding at a time, or the worker piles up stale reads
    let mut polling = true;
    let _ = app.jobs.send(Job::Poll(true));
    let mut next_poll = Instant::now();
    let mut empty_since: Option<Instant> = None;

    let result = ratatui::run(|term| -> Result<(), Box<dyn Error>> {
        loop {
            term.draw(|f| draw(f, &app))?;

            if event::poll(Duration::from_millis(60))?
                && let TermEvent::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
            {
                let ctrl_c =
                    k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c');
                if ctrl_c || !app.key(k.code) {
                    break;
                }
            }

            while let Ok(ev) = ev_rx.try_recv() {
                match ev {
                    Event::Pad(p) => {
                        let now = Instant::now();
                        if p == Pad::Empty {
                            empty_since.get_or_insert(now);
                        } else {
                            empty_since = None;
                        }
                        // Anything shorter than EMPTY_HOLD is a dropped command,
                        // and acting on it flashes "empty" under a still tag
                        let settled =
                            p != Pad::Empty || empty_since.is_some_and(|t| now - t >= EMPTY_HOLD);
                        if settled {
                            // No log line; the Pad panel is the display
                            app.pad = p.clone();
                            if let Pad::Lf { id, .. } = p {
                                app.seed(id);
                            }
                        }
                        app.polls += 1;
                        polling = false;
                        next_poll = now + Duration::from_millis(idle_gap);
                    }
                    Event::Log(m, bad) => app.log(m, bad),
                    Event::Busy(w) => app.busy = Some(w),
                    Event::Idle => {
                        app.busy = None;
                        // A sweep or write leaves the reader dropping commands, so
                        // polling straight back on top flashes the pad empty
                        empty_since = None;
                        next_poll = Instant::now() + Duration::from_millis(idle_gap * 2);
                    }
                    Event::Sector(s) => app.dump.push(s),
                    Event::Block(b, r) => app.blocks[b as usize] = Some(r),
                }
            }

            // Never poll over the top of real work
            if !polling && app.busy.is_none() && Instant::now() >= next_poll {
                polling = true;
                let _ = app.jobs.send(Job::Poll(app.polls.is_multiple_of(HF_EVERY)));
            }
        }
        Ok(())
    });

    let _ = app.jobs.send(Job::Quit);
    drop(app);
    let _ = handle.join();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    const W: u16 = 100;

    /// One frame as text, so a pane sized to nothing shows as a missing string
    fn render(app: &App) -> String {
        let mut term = Terminal::new(TestBackend::new(W, 30)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        term.backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    fn app() -> App {
        App::new(channel().0)
    }

    fn type_in(a: &mut App, s: &str) {
        for c in s.chars() {
            a.key(KeyCode::Char(c));
        }
    }

    /// Reading a tag then lifting it off to fit a blank must not lose the ID
    #[test]
    fn the_pad_does_not_clobber_a_captured_id() {
        let mut a = app();
        let fob = [0x12, 0x34, 0x56, 0x78, 0x9a];

        a.pad = Pad::Lf {
            id: fob,
            freq: 125_000,
        };
        a.seed(fob);
        assert_eq!(a.id, fob);

        a.pad = Pad::Empty;
        assert_eq!(a.id, fob, "survives the tag coming off");

        let blank = [0xde, 0xad, 0xbe, 0xef, 0x01];
        a.pad = Pad::Lf {
            id: blank,
            freq: 125_000,
        };
        a.seed(blank);
        assert_eq!(a.id, fob, "a second tag does not overwrite the buffer");

        let out = render(&a);
        assert!(out.contains("12 34 56 78 9a"), "buffer: {out}");
        assert!(out.contains("de ad be ef 01"), "pad: {out}");

        a.key(KeyCode::Char('c'));
        assert_eq!(a.id, blank, "c is how you take the new one");
    }

    /// Typed input outranks the pad even before anything has been captured
    #[test]
    fn typing_locks_the_buffer_against_the_pad() {
        let mut a = app();
        a.key(KeyCode::Char('e'));
        for _ in 0..14 {
            a.key(KeyCode::Backspace);
        }
        type_in(&mut a, "de ad be ef 01");
        a.key(KeyCode::Enter);
        assert_eq!(a.origin, Origin::Typed);

        a.seed([0x12, 0x34, 0x56, 0x78, 0x9a]);
        assert_eq!(a.id, [0xde, 0xad, 0xbe, 0xef, 0x01]);
    }

    /// The point of the Tag screen: type in one form and see the others
    #[test]
    fn typing_a_decimal_id_updates_the_other_forms() {
        let mut a = app();
        a.key(KeyCode::Down);
        assert_eq!(a.form, IdForm::Dec10);

        a.key(KeyCode::Char('e'));
        assert!(a.editing);
        for _ in 0..12 {
            a.key(KeyCode::Backspace);
        }
        type_in(&mut a, "0016909060");
        a.key(KeyCode::Enter);

        assert_eq!(a.id, [0x00, 0x01, 0x02, 0x03, 0x04]);
        let out = render(&a);
        assert!(out.contains("00 01 02 03 04"), "hex form: {out}");
        assert!(out.contains("00200772"), "dec3+5 form: {out}");
        assert!(out.contains("block 1"), "and what it encodes to");
    }

    #[test]
    fn a_half_typed_id_does_not_become_the_one_that_gets_written() {
        let mut a = app();
        a.id = [1, 2, 3, 4, 5];
        a.sync_field();
        a.key(KeyCode::Char('e'));
        type_in(&mut a, "zz");

        assert!(a.field_err.is_some(), "field is flagged");
        assert_eq!(a.id, [1, 2, 3, 4, 5], "id untouched by the bad text");
        assert!(
            render(&a).contains("bad hex"),
            "and the reason is on screen"
        );

        a.key(KeyCode::Enter);
        a.stage_write_lf();
        assert!(
            a.confirm.is_none(),
            "will not stage a write while unparseable"
        );
    }

    /// Every keystroke reparses into `id`, so Esc needs the snapshot to undo
    #[test]
    fn esc_restores_the_id_that_editing_started_from() {
        let mut a = app();
        a.id = [0x12, 0x34, 0x56, 0x78, 0x9a];
        a.origin = Origin::Captured;
        a.sync_field();
        a.key(KeyCode::Char('e'));
        for _ in 0..14 {
            a.key(KeyCode::Backspace);
        }
        type_in(&mut a, "de ad be ef 01");
        assert_eq!(a.id, [0xde, 0xad, 0xbe, 0xef, 0x01]);

        a.key(KeyCode::Esc);
        assert_eq!(a.id, [0x12, 0x34, 0x56, 0x78, 0x9a], "reverted");
        assert_eq!(a.origin, Origin::Captured);
        assert_eq!(a.field.value, "12 34 56 78 9a");
    }

    #[test]
    fn keys_typed_into_a_field_are_not_commands() {
        let mut a = app();
        a.key(KeyCode::Char('4'));
        a.key(KeyCode::Char('e'));
        let before = a.console.value.clone();
        type_in(&mut a, "q1w");
        assert!(a.editing, "still editing after typing q");
        assert_eq!(a.console.value, format!("{before}q1w"));
        assert_eq!(a.screen, Screen::Console, "the 1 did not switch screens");
    }

    #[test]
    fn the_write_confirmation_names_the_tag_it_would_erase() {
        let mut a = app();
        a.id = [0x12, 0x34, 0x56, 0x78, 0x9a];
        a.sync_field();
        a.pad = Pad::Lf {
            id: [0xde, 0xad, 0xbe, 0xef, 0x01],
            freq: 125_000,
        };
        a.stage_write_lf();

        let out = render(&a);
        assert!(out.contains("Write 12 34 56 78 9a"), "target ID: {out}");
        assert!(out.contains("de ad be ef 01"), "the ID being erased: {out}");
        assert!(out.contains("WARNING"));
        assert!(
            out.contains("y  go ahead"),
            "hints switch to the confirm keys"
        );
    }

    /// A wrong config word makes the tag invisible, so block 0 has to warn
    #[test]
    fn writing_block_zero_warns_about_the_config_word() {
        let mut a = app();
        a.key(KeyCode::Char('3'));
        a.block_field.set("00 14 80 40");
        a.stage_write_block();
        let out = render(&a);
        assert!(out.contains("Write 00 14 80 40 to block 0"), "{out}");
        assert!(out.contains("config word"), "{out}");

        a.key(KeyCode::Char('y'));
        a.key(KeyCode::Down);
        a.stage_write_block();
        assert!(!render(&a).contains("config word"), "block 1 does not warn");
    }

    #[test]
    fn a_bad_block_length_is_refused_rather_than_padded() {
        let mut a = app();
        a.block_field.set("00 14 80");
        a.stage_write_block();
        assert!(a.confirm.is_none());
        assert!(a.log.iter().any(|(m, bad)| *bad && m.contains("4 bytes")));
    }

    #[test]
    fn only_y_confirms() {
        let mut a = app();
        a.stage_write_lf();
        a.key(KeyCode::Char('w'));
        assert!(a.confirm.is_none(), "cancelled");

        a.stage_write_lf();
        assert!(a.key(KeyCode::Char('q')), "q while confirming cancels");
        assert!(a.confirm.is_none());
    }
}
