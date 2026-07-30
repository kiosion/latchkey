# wCopy Smart Reader host protocol

Recovered by static analysis of the vendor's Windows binary without execution.

    wCopy_2024010501.zip  sha256 5dc1ef2d5e31422c2d6103ddac763490898a37ade00c5888463c84d7de9ff650
    wCopy_2024010501.exe  sha256 33b7ee8b70b5322a2db0bd3b0b92b8bab2f8328c06b215dac2fc58cdbc962dfd

PE32 x86 MFC, built 2024-01-05, 6435840 bytes.

**Confirmed**: reproduced on hardware.
**Recovered**: read from the disassembly and implemented, untested.
**Inferred**: a reading the disassembly does not settle.

Confirmed here means one reader (USB `2518:6018`, `wCopy NSR109-HIDIC V806N`),
one tag family (EM4100 fobs, T5577 blanks), one carrier (125 kHz). Enough to
trust the framing, the `0x65` read, and the `0x66` code `0x13` write against
blocks 0-2. Treat everything outside that as untested.

## Device

    USB VID 0x2518  PID 0x6018

Raw HID, no report IDs, 64-byte input and output reports:

    05 01  Usage Page (Generic Desktop)     95 40  Report Count 64
    09 00  Usage (undefined)                75 08  Report Size 8
    a1 01  Collection (Application)         81 02  Input  (Data,Var,Abs)
    15 00  Logical Min 0                    91 02  Output (Data,Var,Abs)
    25 ff  Logical Max 255                  c0
    19 01  Usage Min 1
    29 08  Usage Max 8

Poll-only. A 25-second listen on a freshly replugged reader holding a detected
tag captured zero input reports.

A global at `0x9ae6720` holds the connected product ID. Builders branch on it
against `0xb030`, `0x6022`, `0xb058`, `0x6018` and `0xb029`, which is how one
binary drives five variants and why some builders emit functions this reader
rejects.

## Framing (confirmed)

    off  value
    0    0x00                 hidapi report-ID byte, absent on the wire
    1    0x01 out / 0x02 in   direction magic
    2    LEN = payload_len+6  counts offsets 1..=LEN
    3    seq & 0xff           16-bit, little endian
    4    seq >> 8
    5..  payload
    5+n  checksum
    6+n  0xFE out / 0xFD in

    checksum = (~sum(frame[1 .. payload_len+4])) & 0xff

Same checksum both directions. The device answers `seq + 1`, which is why the
vendor's sequence global steps by 2. Max payload 58 bytes. Replies carry no
report-ID byte, and every offset shifts down by one inbound.

    tx  00 01 0d 00 00 ff 00 00 00 02 d4 02 1a fe
    rx  02 0e 01 00 d5 03 32 01 06 07 90 00 46 fd

`d5 03 32 01 06 07` is the PN533 GetFirmwareVersion answer (IC 0x32, version
1.6, support 0x07). The `90 00` is an ISO 7816 status word the reader appends.

## Payload shape (confirmed)

    ff <ins> <p1> <p2> <lc> <data...>

`lc` counts `data` only. Every command builder emits this shape and funnels into
one frame builder at `0x40f0b0`.

This is an ACR122U convention. `FF 00 40 50 04 05 05 03 01`, the documented
ACR122U LED and buzzer APDU, sounds the buzzer three times to match its `03`
repeat count and answers `90 01`. The device isn't an ACR122U, but that command
set is a useful map.

Every builder uses `ins = 0x00`, the vendor namespace, where `p1` selects the
function and `p2` is its argument. `p1 = 0x00` is PN533 passthrough with `data`
starting at the `0xD4` host-to-controller TFI, documented in the NXP PN533
manual. The 125 kHz side is separate silicon behind vendor functions.

A one-byte payload is a status. `fd` rejects the command, which reads as "bad
length or parameters" since almost every `p1` answers it to a zero-length body.
`00` means in-range with nothing to report. Longer payloads are data, optionally
ending in `90 xx`.

## Command surface

Recovered by summarizing every caller of the frame builder at `0x40f0b0`. That
enumerates the set exhaustively and yields 42 wrappers.

| p1 | sub or code | reply | what it is |
|----|-------------|-------|------------|
| 00 | `d4 42` | `90 00` | PN532 InCommunicateThru |
| 00 | `d4 40 01 30 <blk>` | 16 bytes + `90 00` | MIFARE read block |
| 00 | `d4 40 01 a0 <blk> <16>` | `90 00` | MIFARE write block |
| 00 | caller-supplied `d4 ...` | var | generic PN532 passthrough, 24 call sites |
| 40 | `<led> 04 <t1> <t2> <reps> <buzz>` | `90 01` | LED and buzzer |
| 61 | `01` | `90 00` | card activate, precedes every MIFARE read |
| 62 | `01` | `90 00` | card release, 48 call sites |
| 65 | `p2 = 08` | `05` + 5 | 125 kHz ID read |
| 66 | 18 codes | var | 125 kHz block and raw family |
| 6a | `01` | 7 bytes | 13.56 MHz detect |
| 6b | `30`, `31` | 16 or 32 bytes | rejected by this reader with `63 00` |
| 68 | `00` | `wCopy NSR109-HIDIC V806N` | model string |
| 69 | `00` | `T37350466633` | serial string |
| 80 | `00 01 11 12 14 19 21 22` | var | reader-level |
| 82 | `00 04 05 07` | var | reader configuration |

`p1 = 0x62` is a control command whose result the vendor discards. Both exit
paths of `0x40de60` do `xor eax, eax`, and it checks only for LEN 8 with reply
byte 4 as `0x90`. That is the two-byte payload `90 00`. An empty pad answers
seven zero bytes instead, which is why this looks like a read and is not one.

Six `ins` bytes answer with `p1 = p2 = 00`, exactly the ISO 7816 and PC/SC
contactless-storage-card instructions. All return `63 00` ("no card selected")
except `ca`, which returns an all-zero UID plus `90 00`:

    82 EXTERNAL AUTH   86 GENERAL AUTH   88 INTERNAL AUTH
    b0 READ BINARY     ca GET DATA       d6 UPDATE BINARY

    read   ff b0 <addr_hi> <addr_lo> <le>
    write  ff d6 <addr_hi> <addr_lo> <lc> <data...>

`p1 = 0x67` answers with a LEN byte of `0x41`, declaring 65 bytes, and delivers
one report (layout unknown).

### Buzzer and LED

    ff 00 40 50 04 <t1> <t2> <repeats> <buzzer link>

The buzzer works. `repeats` counts the beeps, confirmed against `03`. `t1` and
`t2` are the on and off phases in hundredths of a second. The builder divides
the duration its caller asks for by ten before storing it in one of them.

`p2` is `0x50` and nothing else. The binary holds exactly one `0x40` builder, at
`0x406c70`, and all three of its product branches store `0x50` as a literal. The
software has no LED feature, and no LED, lamp or indicator string anywhere. That
leaves nothing to copy.

Read as an ACR122U, `p2` would be its LED state byte and `0x50` would be red
blink only, which is a tidy story with no evidence behind it. The reader accepts
every `p2` value with `90 01`, and none of them has moved the LED. The `01` is
constant and does not report LED state.

The reader lights green on its own when it detects a tag. The hardware is there
and the host command for it is not in this binary.

The twenty reader-level subcommands that answer `00` with no known effect were
the last place to look, and they came up empty. Each of `0x80` `01` to `0f` and
`0x82` `01` to `05` went out against an empty pad, three seconds apart, with
someone watching the reader. No LED change and no audible change. `ff 00 82 00
00` read back byte-identical afterwards, which rules out a silent persisted
setting. All twenty are safe to send. Going one past either end wedges the
reader.

That leaves `0x67`, whose 65-byte reply has no known layout, and the `p1` space
above `0x6f`, which cannot be swept without hitting the wedge. Neither is
promising. The working assumption is now that firmware drives this reader's LED
on tag detect and no host command reaches it.

## 125 kHz ID read (confirmed)

    ff 00 65 08 <lc> <freq LE32> <w1 LE16> <w2 LE16>

    tx  ff 00 65 08 18 48 e8 01 00 00 00 00 00
    rx  05 c0 ff ee 00 01

The reply is a length byte then that many bytes. `05` plus five bytes is an
EM4100 ID. `0x1e848` is 125000, the carrier in Hz, carried as a little-endian
dword by every 125 kHz command.

`lc` sits where an APDU length belongs but is not one; eight data bytes always
follow. The vendor pairs one `lc` per carrier. `w1` and `w2` look like
demodulator thresholds.

Both `p2` and `lc` are caller-supplied. The builder pre-fills `65 05 1e` and then
overwrites offsets 3 and 4 from its arguments. The `05` and `1e` sitting in the
template are defaults no call site uses.

From `0x408cc0`, the most-called command in the binary at ~60 sites, all with
`p2 = 0x08`. On LEN `0x0c` with `payload[0] == 5` it copies five bytes out. The
profiles its auto-detect sweeps, in order:

| freq | lc | w1 | w2 |    | freq | lc | w1 | w2 |
|------|----|----|----|----|------|----|----|----|
| 125000 | 18 | 0000 | 0000 | | 125000 | 18 | 0181 | 0118 |
| 250000 | 04 | 0000 | 0000 | | 175000 | 04 | 00bb | 0096 |
| 375000 | 02 | 0000 | 0000 | | 250000 | 04 | 00bb | 0096 |
| 500000 | 01 | 005d | 004b | | 300000 | 04 | 00bb | 0096 |
| | | | |                     | 375000 | 02 | 008b | 0070 |
| | | | |                     | 500000 | 01 | 005d | 004b |

Only the first has ever returned data for me. The profiles are not
tag-exclusive. An EM4100 fob that answers at 125 kHz also answers the 175 kHz
profile.

## 125 kHz block write (confirmed)

    ff 00 66 00 1e <freq LE32> 13 00 <blk> <data 4> <key 4>

From `0x40c440`. The 4-byte key is always the ASCII bytes `54 69 61 6e`, "Tian".
Not a T5577 password; it sits in a field of its own after the block data and
never varies.

Writing an EM4100 ID onto a blank T5577:

| blk | data | what |
|-----|------|------|
| 0 | `00 14 80 40` | config: ASK/Manchester, RF/64, two data blocks, no password |
| 1 | frame[0..4] | first 32 bits of the EM4100 frame |
| 2 | frame[4..8] | last 32 bits |

Block 0 is mandatory; writing only 1 and 2 leaves the tag silent and
undetectable, which is the state a fresh blank arrives in. The vendor's own
write path does not send block 0 and must configure the tag some other way.

The frame is standard EM4100 with nine 1 bits, each of the ten ID nibbles followed
by its even parity bit, four column parity bits across the nibbles, a 0 stop
bit. Most significant bit first into block 1.

Every write answers `00`. Its own caller in the vendor binary validates against
`05` plus five bytes, which never arrives. Reading the tag back is the only
trustworthy check I've found.

## The 0x66 family

All 18 codes share `ff 00 66 00 1e <freq LE32> <code> <args>`. Sorted by
argument length, since a destructive write must carry either 32 bits of block
data or a 5-byte ID:

| code | arg bytes | reply | known |
|------|-----------|-------|-------|
| 41 | 1 | `04` + 4 | sampler start |
| 46 | 1 | `28` + 40 | fetch 40 raw samples |
| 12 | 4 | `05` + 5 | pre-write step, see below |
| 21 | 4 | `05` + 5 | called by the vendor's write path |
| 1f, 2f, 3f, 4f | 4 | `05` + 5 | |
| 22, 32, 33, 34, 43, 44 | 4 | `05` + 5 | |
| 42 | 4 | `09` + 9 | the only one with a 9-byte reply |
| 01 | 5 | `05` + 5 | |
| 13 | 8 | `05` + 5 | block write |
| 40 | 22 | `04` + 4 | sampler config, tail `3c b4 64` |

Code `0x12` is not a block read, and nothing else is either. Its builder at
`0x40c260` takes the block number and a pointer to four bytes. The write path at
`0x4172a0` hands it the very bytes it is about to write, sleeps 15 ms, and sends
`0x13` with those same bytes plus the key. That makes `0x12` a pre-write step. It
validates its reply as `05` plus five bytes, the shape of an ID rather than of a
32-bit block.

That closes the question for the whole family. Every `0x66` code validates a
5-byte ID reply except the three sampler codes. No command in this protocol
returns the contents of a T5577 block. A tag can be written and then identified
by what it emits. It cannot be read back block by block.

`0x40a5a0` is a raw sampler: code `40` to configure, sleep 30 ms, code `41` with
argument 5, two code `46` fetches of 40 bytes at offsets 0 and 40, and a scan of
the 80 bytes for `ff ff ff`. This is the route to 125 kHz protocols other than
EM4100.

Codes `41` and `46` work without the code `40` step (confirmed). `41` arms the
sampler and answers `00`; `46` returns 40 bytes of demodulator output. A second
fetch at offset 40 gets no reply. Where the vendor reads 80 bytes latchkey reads
40. An empty pad comes back 94 to 100 per cent ones, often every byte
`ff`. `latchkey sample` prints them with the count.

`0x417xxx` holds two write paths. `0x4172a0` is the `0x12` and `0x13` pair above.
A separate one from `0x417d60` calls codes `21` and `22` in a loop with sleeps,
formatting with `%10.10u`. Neither has been sent.

## Pacing, and the reader's own detection

The reader drops commands if pushed. After one successful read the next few get
no reply before it recovers. The vendor sleeps 30 ms between 125 kHz commands.
latchkey holds 40 ms between any two, gated in one place so every path pays it.

A `0x65` read of an empty pad takes 700 to 1100 ms to answer its `00`, and about
half the time never answers at all. Giving up early has a price. The reader
finishes the command in its own time and stamps the answer it owes onto the next
request. A host that abandons a read gets `00` to whatever it asks next, with a
correct checksum and the new sequence number:

    ff 00 65 08 18 ...       abandoned after 50 ms
    ff 00 00 00 02 d4 02  -> 00
    ff 00 00 00 02 d4 02  -> d5 03 32 01 06 07 90 00

One bogus reply per abandoned command, no more. latchkey waits 1200 ms on a
poll, which makes this rare. It re-sends once when a `00` arrives on the heels
of a timeout.

The reader also detects tags in firmware, announcing it with two beeps and a
green LED that holds while the tag sits there. Only a detected tag answers the
`0x65` read, and that detection needs the reader idle. Polling every few hundred
milliseconds starves it. The beeps and LED stop. A tag set down while the host
polls never becomes readable, however many times it is asked. A tag detected
before the polling started keeps reading fine, which makes this easy to miss.

Around 1.5 s of quiet per poll works on this reader. The threshold is not
measured; `--poll-gap` and `watch --gap` exist to find it. This is the likeliest
thing to differ on other models.

Whether a command re-arms the detector is unknown. `0x62`, card release, has 48
call sites and is the obvious candidate, but its result is discarded and its
effect on the 125 kHz side is untested.

## 13.56 MHz (recovered, untested)

Nothing here has been run against a card.

The 13.56 MHz side is a stock PN532 behind a passthrough. `0x40db60` takes an
entire PN532 frame from its caller and 24 sites use it. MIFARE authenticate is
one of them, built caller-side, which is why no wrapper carries a `0x60` opcode.
The vendor binary stops mattering from here; the PN532 manual is the spec.

    detect    ff 00 6a 01 00 08
    activate  ff 00 61 01
    release   ff 00 62 01 00
    read      ff 00 00 00 <lc> d4 40 01 30 <blk>
    write     ff 00 00 00 <lc> d4 40 01 a0 <blk> <16>
    auth      ff 00 00 00 <lc> d4 40 01 <60|61> <blk> <key 6> <uid 4>

The detect reply is `07` plus seven bytes. The parser at `0x406fa3` copies byte 1
to a one-byte output and bytes 2-7 to a six-byte one, which is SAK then ATQA then
UID. The order within those six is settled by what the parser does next: it
retries the whole detect while byte 0 of the six is non-zero. That only makes
sense for an ATQA high byte, which is `00` for every common answer (`00 04`,
`00 02`, `00 44`). A UID first byte would fail that test on nearly every card.

The MIFARE reply shapes are pinned by the vendor's own offset checks rather than
by inference. Read at `0x40e960` wants LEN `0x1b` with `d5 41` at payload 0 and
`90` at report offset 23, which is `d5 41 <status> <16 bytes> 90 00`. Write at
`0x40eb00` wants LEN `0x0b` and `90` at offset 7, which is `d5 41 <status> 90 00`.

One inference is left. Card type comes from the published SAK table. The vendor's
own tree at `0x407031` compares against `0x20` and masks with `0xfc` in a way not
worked out. Its format strings print a 4-byte UID for Classic and a 7-byte UID
for UltraLight and DESFire. The 4 bytes latchkey keeps cover the Classic case
only.

The vendor does not recover unknown keys. `0x4281a0`, `0x43fc60` and `0x45fd40`
reference `%s/keys/a%08x.dump` and `%s/keys/b%08x.dump`: per-UID key files on
disk, fed to the reader.

## Reader-level commands

| p1 | p2 | reply |
|----|----|-------|
| 80 | 00 | `12 4e 38 4e 47 11 2c 03 53 38 4b 47 53 2d 00 20 0f 78 b6` |
| 80 | 01-0f | `00` |
| 80 | 10+ | none, and the reader wedges |
| 82 | 00 | `10 00 07 01 40 01 f0 00` then zeros, looks like configuration |
| 82 | 01-05 | `00` |
| 82 | 06+ | none, and the reader wedges |

The vendor issues `80 11`, `80 12`, `80 14` and `80 19`, all past the range this
reader answers. Either they need an unreached state or they target another
variant. A blank 125 kHz tag on the pad changes nothing in either sweep. Neither
family is a tag read path. Handler `0x45e570` prints `Rf config : %2.2X` seven
times then `done`, which is the `0x82` family.

### Hazard: subcommands past the end of a table

Subcommands in range answer. The first out of range gets silence, the next also,
and the one after that fails at `IOHIDDeviceSetReport` with an I/O Timeout. That
reads like an unbounded jump table taking the USB stack down with it. Only the
first silent subcommand does damage; everything after is a dead device being
talked to. Unplug and replug. Nothing is written to flash and the reader has
come back every time.

## Still unknown

- Which `p1` values above `0x6f` exist. Sweeping them risks the wedge above.
- The purpose of `0x66` codes `01`, `1f`, `22`, `2f`, `32`, `33`, `34`, `3f`,
  `42`, `43`, `44` and `4f`. Codes `32`, `33`, `34`, `22`, `21`, `43`, `44` and
  `42` all carry four caller-supplied bytes at 125 kHz, the same shape as the
  write payload. Keep those away from a tag that matters.
- Whether `ff 00 83 <16 bytes>` writes the configuration that `ff 00 82 00 00`
  reads. `p1 = 0x83` rejects a zero-length body with `fd`, which is consistent.
  It may hold the antenna selector. Untested, because a bad configuration write
  lands on the reader rather than on a tag.
- The `0x67` reply layout.
- Why nothing reacts to a blank 125 kHz tag. All three of `ff ca 00 00 00`,
  `ff b0 00 <addr> 04` and `ff 00 62 00 00` answer as if no card were present. A
  blank T5577 may equally have nothing an EM4100 read would return. The raw
  sampler is the one lead. A tag loads the antenna whether or not it modulates,
  and its 40 bytes may separate a blank from an empty pad where no decoded
  command can. Needs someone to run `latchkey sample` both ways and compare.
- Whether the LED is reachable from the host at all. Everything addressable has
  been tried. See the buzzer section.

## How this was recovered

Two scripted passes over the binary, neither needing the reader itself.

The command set comes from the frame builder at `0x40f0b0`. Every command is
staged into a stack buffer and passed to it; summarizing its callers enumerates
its surface.

The meanings come from the call graph. This is an MFC app, and each wrapper is
called from a dialog handler that formats its own status text. Walking callers
upward to the first function referencing string literals labels the wrapper with
the vendor's own UI copy. `0x418a00` carries `Atqa: %2.2x%2.2x  Sak: %2.2x` and
`NXP MIFARE CLASSIC 1K`, identifying `0x6a`. `0x451750` separates
`Mifare DESFire EV1`, `Mifare UltraLight` and plain `Mifare` from ATQA and SAK.
The `%10.10u` and `%3.3u%5.5u` formats at `0x43af26` and `0x43af74` appear only
in handlers calling the `0x65` read, which is where the two decimal ID
renderings come from.
