# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Tools for WarFront: Turning Point (2007 RTS), all behind one CLI, `warfront.py`:

- `inf` (`decompress_inf.py`): converts binary INF to the game's text format and compiles text back to binary. Binary -> text -> binary is byte-exact for every shipped file.
- `widescreen` (`widescreen.py`): builds a widescreen interface patch from the game's own files.
- `launch` / `patch-demo` (`editor_unlock.py`): unlocks the hidden CoE level editor and Debug Mode in `WarFront.exe`, in memory (retail, encrypted on disk) or on disk (SP demo).

## Commands

```bash
python warfront.py inf -t -d Inf Inf_text          # binary -> text
python warfront.py inf -b -d Inf_text Inf_binary   # text -> binary
python warfront.py inf -t -f input.inf output.inf  # single file
python warfront.py inf -d Inf Inf_decompressed     # decompress only
python warfront.py inf -a file.inf                 # show structure

python warfront.py widescreen GAME_DIR --inf GAME_DIR/Inf_backup -o OUT   # widescreen patch

python warfront.py launch GAME_DIR/WarFront.exe --editor [--debug-mode]  # Windows only
python warfront.py patch-demo SPDEMO/Run/WarFront.exe                    # writes WarFront_editor.exe

python -m unittest discover -s tests                  # unit tests
WARFRONT_DIR=/mnt/c/Users/balcs/Documents/warfronts/retail_hun \
WARFRONT_INF_DIR=/mnt/c/Users/balcs/Documents/warfronts/retail_hun/Inf_backup \
WARFRONT_DEMO_EXE=/mnt/c/Users/balcs/Documents/warfronts/spdemo/Run/WarFront.exe \
  python -m unittest discover -s tests                # + round trip, patch build and demo exe check
```

`decompress_inf.py` and `widescreen.py` still run standalone with the same options; their `main(argv, prog)` is what `warfront.py` calls.

No external dependencies beyond Python 3.6+. Run the game-file tests under WSL/Linux: the Windows Python 3.14 build uses zlib-ng, which compresses differently, so byte-exact recompression fails there even though the decompressed data is identical.

## Architecture

Everything INF is one tree model (`Node`: name, ordered `(name, values)` props, children):

- `read_binary` / `write_binary`: decompressed binary <-> tree
- `decompress` / `compress`: 12-byte header (`magic, 1, uncompressed_size`) + zlib
- `to_text` / `parse_text`: tree <-> text (`parse_text` also expands object-like `#define` macros)
- `detect_format`: 'compressed', 'binary' (decompressed), 'text' or None, decided by content

Binary layout: `sto, root_prop_count, root_child_count`, then root props and child nodes. Every section and object is the same node record (`name_idx, prop_count, child_count, props, children`). There are no separate "simple", "object" or "terraintypetable" formats. Version 3 (`AA A5 FF FF`) uses u32 string indices; version 2 (`AB A5 FF FF`) uses u16. The string table is numbered in first-use order during a depth-first walk, which is what makes the round trip byte-exact. The format spec lives in README.md.

`widescreen.py` rewrites the Prism UI screens (`Inf/2Prism`) for a wider virtual width: it shifts only screen-space coordinates (see README "Widescreen Patch" for the Position/skin rules), cuts the bottom HUD image into three pieces and widens full-width decorations by remapping image columns (`WIDE_ART`). Images are uncompressed 32-bit TGA, handled with the stdlib `Tga` class. It must be run on original files (it refuses an already-patched `centralpanel.inf`).

`editor_unlock.py` holds a `BUILDS` table per exe (VA of `push offset "game"`, its original bytes, the `"editor"` string VA, the game-app global). `detect_build` and `has_debug_accessors` take a `read(address, size)` callable so they are tested against fake memory; only `Process`/`launch` touch kernel32 (imported lazily, so the module imports on Linux). `launch` busy-waits for the decrypted patch site because the retail exe is encrypted on disk. Details and addresses: `docs/editor-unlock.md`.

`_RefID` is a normal property and is written exactly as stored. `--add-refids` optionally adds sequential IDs to files that have none; the game doesn't need it.

## Test Data

Game installs are under `C:\Users\balcs\Documents\warfronts\` (`/mnt/c/Users/balcs/Documents/warfronts/` in WSL):

- `retail_hun`: compressed binaries (the main round-trip corpus); `Inf_backup` holds the original `Inf`
- `mpdemo-10tacle`: compressed binaries
- `spdemo`, `salespreview`: mostly developer-written text INF files, the reference for text syntax; `spdemo\Run\WarFront.exe` is the SP demo 1.01 exe for the editor patch

In-game testing: back up `retail_hun\Inf\`, copy `-t` output **over** it (the folder also holds non-INF files such as `Physics\physics.phy`), then check the menus and start a mission. The retail `Settings.setting` already has `binaryinffiles = 0` and loads both formats. Verified 2026-09-27 with all 1,093 retail `Inf` files converted to text (no `--add-refids`). The game rewrites the text file `Inf\bases\baseinfos.inf` at startup, so expect it to differ from the converted copy. The editor also rewrites some `Inf` files and adds `editor\...` keys to `Local Settings.setting`.
