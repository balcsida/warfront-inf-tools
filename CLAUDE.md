# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Tools for WarFront: Turning Point (2007 RTS) binary INF configuration files. `decompress_inf.py` converts binary INF to the game's text format and compiles text back to binary. Binary -> text -> binary is byte-exact for every shipped file.

## Commands

```bash
python decompress_inf.py -t -d Inf Inf_text          # binary -> text
python decompress_inf.py -b -d Inf_text Inf_binary   # text -> binary
python decompress_inf.py -t -f input.inf output.inf  # single file
python decompress_inf.py -d Inf Inf_decompressed     # decompress only
python decompress_inf.py -a file.inf                 # show structure

python widescreen.py GAME_DIR --inf GAME_DIR/Inf_backup -o OUT   # widescreen patch

python -m unittest discover -s tests                  # unit tests
WARFRONT_DIR=/mnt/c/Users/balcs/Documents/warfronts/retail_hun \
WARFRONT_INF_DIR=/mnt/c/Users/balcs/Documents/warfronts/retail_hun/Inf_backup \
  python -m unittest discover -s tests                # + round trip and patch build on a game install
```

No external dependencies beyond Python 3.6+.

## Architecture

Everything is one tree model (`Node`: name, ordered `(name, values)` props, children):

- `read_binary` / `write_binary`: decompressed binary <-> tree
- `decompress` / `compress`: 12-byte header (`magic, 1, uncompressed_size`) + zlib
- `to_text` / `parse_text`: tree <-> text
- `detect_format`: 'compressed', 'binary' (decompressed), 'text' or None, decided by content

Binary layout: `sto, root_prop_count, root_child_count`, then root props and child nodes. Every section and object is the same node record (`name_idx, prop_count, child_count, props, children`). There are no separate "simple", "object" or "terraintypetable" formats. Version 3 (`AA A5 FF FF`) uses u32 string indices; version 2 (`AB A5 FF FF`) uses u16. The string table is numbered in first-use order during a depth-first walk, which is what makes the round trip byte-exact. The format spec lives in README.md.

`widescreen.py` rewrites the Prism UI screens (`Inf/2Prism`) for a wider virtual width: it shifts only screen-space coordinates (see README "Widescreen Patch" for the Position/skin rules), cuts the bottom HUD image into three pieces and widens full-width decorations by remapping image columns (`WIDE_ART`). Images are uncompressed 32-bit TGA, handled with the stdlib `Tga` class. It must be run on original files (it refuses an already-patched `centralpanel.inf`).

`_RefID` is a normal property and is written exactly as stored. `--add-refids` optionally adds sequential IDs to files that have none; the game doesn't need it.

## Test Data

Game installs are under `C:\Users\balcs\Documents\warfronts\` (`/mnt/c/Users/balcs/Documents/warfronts/` in WSL):

- `retail_hun`: compressed binaries (the main round-trip corpus)
- `mpdemo-10tacle`: compressed binaries
- `spdemo`, `salespreview`: mostly developer-written text INF files, the reference for text syntax

In-game testing: back up `retail_hun\Inf\`, copy `-t` output **over** it (the folder also holds non-INF files such as `Physics\physics.phy`), then check the menus and start a mission. The retail `Settings.setting` already has `binaryinffiles = 0` and loads both formats. Verified 2026-09-27 with all 1,093 retail `Inf` files converted to text (no `--add-refids`). The game rewrites the text file `Inf\bases\baseinfos.inf` at startup, so expect it to differ from the converted copy.
