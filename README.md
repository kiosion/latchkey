# latchkey

A host-side driver/TUI for NSCCN wCopy-family RFID readers, on macOS and
Linux. These readers ship with Windows-only software; latchkey speaks the same
USB protocol natively.

Reads and writes 125 kHz tags, identifies and reads 13.56 MHz cards, and exposes
the reader's raw command interface.

Not affiliated with NSCCN; the protocol was recovered by static analysis of the
vendor's Windows binary. [docs/PROTOCOL.md](docs/PROTOCOL.md) is its reference.
This was simply written as a fun evening project and because I was too stubborn
to order another reador or spin up my dusty Windows VM.

## How finished is this?

Beta. Alpha, even. Only tested with one reader and one tag family.

|                                   | read          | write               | tried on hardware |
| --------------------------------- | ------------- | ------------------- | ----------------- |
| EM4100 / EM4102 / TK4100, 125 kHz | yes           | read-only by design | yes               |
| T5577 / T5200, 125 kHz            | per block     | per block           | blocks 0-2 only   |
| T5577 wipe, blocks 0-7            | n/a           | yes                 | **no**            |
| MIFARE Classic 1K/4K              | yes           | yes                 | **no**            |
| MIFARE Ultralight, DESFire        | identify only | no                  | **no**            |
| Raw reader commands               | yes           | yes                 | yes               |

"Confirmed" means reproduced on one USB `2518:6018` against EM4100 fobs and
T5577 blanks at 125 kHz. That path works end to end. Everything else is built
from the disassembly alone. Expect rough edges on the tested path too.

## TUI

    latchkey

Left and right move between screens, `1`-`4` jump. Up and down move within one.
`e` edits, `Enter` accepts, `Esc` reverts, `?` lists keys, `q` quits.

A line under the ID names the next useful action for whatever state you are in.

- Tag composes a 125 kHz ID. All three renderings show at once and up/down
  picks which you type in. Both decimal forms are the vendor's own; the 3+5
  split is usually what is printed on the tag. `x` zeroes every block, the way
  back to a blank.
- Card identifies a 13.56 MHz card and dumps MIFARE Classic sectors. `s`
  saves. A sector no key opens reads locked rather than zeroed.
- Blocks is the T5577 block by block. For tags that are not plain EM4100.
- Console sends an arbitrary payload. Up and down walk the commands this
  reader is known to answer and load the one you land on. Length, sequence
  and checksum are added automatically; a bad reply checksum is flagged.

## Command line

Every screen's also a subcommand.

    $ latchkey read
    125000 Hz  lc 18  ID 12 34 56 78 9a

    $ latchkey write "12 34 56 78 9a" --config --yes
    frame  ff 8c a6 4a 98 f8 ca 96
    write block 0 00 14 80 40  -> 00
    write block 1 ff 8c a6 4a  -> 00
    write block 2 98 f8 ca 96  -> 00

    Reading back:
      12 34 56 78 9a  matches

Drop `--yes` to see the plan without sending it.

    $ latchkey wipe --yes
    tag reads 12 34 56 78 9a now

    block 1 <- 00 00 00 00  -> 00
    ...
    block 0 <- 00 00 00 00  -> 00

    nothing reads off it now.

`wipe` zeroes blocks 1 to 7 and then block 0. An interrupted run leaves the tag
still emitting. Afterwards the tag is silent until a `write --config` gives it a
config word again.

`--config` writes block 0, the word that makes a T5577 emit EM4100 at all. A
bag-fresh blank has no valid config, emits nothing, and is invisible to the
reader. `--config` is needed the first time any tag is programmed. Repeating it
is harmless.

## Hardware

    USB 2518:6018   "wCopy Smart Reader"   wCopy NSR109-HIDIC V806N

The vendor binary drives five product IDs (`b030`, `6022`, `b058`, `6018`,
`b029`) and branches on which is connected. Other models likely share the framing
with a different command set. Only `6018` has been tried.

Raw USB HID, which means no kernel driver on macOS. On Linux you want a udev rule
for the hidraw node.

Some undocumented subcommands wedge the reader and need a physical replug.
Nothing observed writes to its flash, and it has recovered every time for me.

## Contributing

This'll probably end up abandoned now that I've written the fobs I needed to,
but, roughly in priority order:

- Run the 13.56 MHz paths against a real card. `latchkey hf --raw` prints the
  detect reply untouched, which is all that is needed to pin the field layout.
- Other wCopy product IDs.
- The unidentified 125 kHz `0x66` codes. `docs/PROTOCOL.md` tables them with
  argument lengths; `lf-probe` sends them at a throwaway tag and reports what
  changed.
- Non-EM4100 125 kHz protocols, via the raw sampler (`0x66` codes `40`, `41`,
  `46`), which returns samples rather than a decoded ID.

## Building

    cargo build --release
    cargo test

## Licence

Apache-2.0.
