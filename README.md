# WarFront: Turning Point - Tools

Modding and reverse-engineering tools for **WarFront: Turning Point** (2007 RTS game by Digital Reality).

## Overview

Everything is available through one command line, `warfront.py`:

| Command | What it does |
|---------|--------------|
| `warfront.py inf` | Convert the game's binary INF configuration files to text and compile them back ([INF tools](#inf-tools)) |
| `warfront.py widescreen` | Build a [widescreen interface patch](#widescreen-patch) from the game's own files |
| `warfront.py launch` | Start the game with the hidden level editor and/or Debug Mode unlocked ([editor unlock](#editor-unlock-and-debug-mode), Windows) |
| `warfront.py patch-demo` | Write an editor-mode copy of the SP demo exe ([editor unlock](#editor-unlock-and-debug-mode)) |

The modules behind them (`decompress_inf.py`, `widescreen.py`, `editor_unlock.py`) can also be imported, and `decompress_inf.py` and `widescreen.py` still run on their own with the same options.

## Installation

```bash
git clone https://github.com/balcsida/warfront-tools.git
cd warfront-tools

# No dependencies beyond Python 3.6+
python3 warfront.py --help
```

## INF Tools

WarFront stores game configuration, UI layouts, unit definitions (`.base`) and player profiles in a compressed binary INF format. `warfront.py inf` (`decompress_inf.py`):

- **Converts** binary INF files to the game's editable text format
- **Compiles** text INF files back to binary (a replacement for Digital Reality's internal `bc.exe`)
- **Decompresses** INF files without converting them
- **Analyzes** INF file structure

Converting binary → text → binary reproduces every binary INF shipped with the retail game and the demos **byte for byte**, compressed stream included (with a standard zlib, see [Known Limitations](#known-limitations)).

The game reads both formats, so edited files can be used either as text (with `binaryinffiles = 0`) or compiled back to binary.

### Binary to Text

```bash
# Default: Inf/ -> Inf_text/
python3 warfront.py inf -t

# Custom input/output directories
python3 warfront.py inf -t -d "Game/Inf" "Output/Inf"

# Single file
python3 warfront.py inf -t -f game.inf game_text.inf

# Convert in place (overwrites the original files)
python3 warfront.py inf -t -i "Game/Inf"
```

### Text to Binary

```bash
# Single file
python3 warfront.py inf -b -f game_text.inf game.inf

# Whole directory
python3 warfront.py inf -b -d Inf_text Inf_binary
```

`-b` compiles every text file it finds, including files the game ships as text (such as `mplayer.inf`); binary files are copied unchanged. Output is version 3 unless `--format-version 2` is given.

### Decompress Only

```bash
python3 warfront.py inf -d Inf Inf_decompressed
```

### Analyze File Structure

```bash
python3 warfront.py inf -a file.inf
```

`python3 decompress_inf.py ...` accepts exactly the same options.

### Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --to-text` | Convert binary INF to text |
| `-b, --to-binary` | Compile text INF to compressed binary |
| (neither) | Decompress only, keeping the binary layout |
| `-d INPUT OUTPUT` | Process directory INPUT into OUTPUT |
| `-i DIR` | Process files in place (overwrites originals) |
| `-f INPUT OUTPUT` | Process a single file |
| `-a FILE` | Show file structure without writing output |
| `--format-version {2,3}` | Binary version written by `-b` (default 3) |
| `--add-refids` | With `-t`, add sequential `_RefID`s to files that have none (see below) |
| `-v, --verbose` | Show detailed output |

Files are processed if they end in `.inf` or `.base`. Each file's format (compressed, decompressed binary or text) is detected from its content, not its name.

### Enabling Text INF in Game

1. Make sure `Settings.setting` in the game folder has `binaryinffiles = 0` (the Hungarian retail release already ships with it, and still loads its binary files)
2. Back up the game's `Inf` folder
3. Copy the converted text files **over** the existing `Inf` folder. Don't replace the folder: it also holds non-INF files the game needs, such as `Physics/physics.phy` and `Triggers/trigger.gvar`

Alternatively, compile your edited text files with `-b` and put the binaries back.

The retail game has been played with every INF and BASE file in `Inf` (1,093 files) replaced by `-t` output: the menus work and missions start and play. The game rewrites `Inf/bases/baseinfos.inf`, which ships as text, at startup.

#### About `_RefID`

`_RefID` is an ordinary property. Digital Reality's text sources give many objects a `_RefID`, but their compiler stripped most of them: of the 1,094 retail binaries, only 55 still contain any. The tool writes exactly what the binary contains, and the game runs fine without the missing IDs. The in-game test above includes `game.inf`, which has none, and the SP demo also ships 59 text files without any.

The retail game doesn't need `--add-refids`. It numbers top-level `Name : cClass` objects plus every `[: cClass]` object in a container, starting at 1. This is the scheme earlier versions of this tool intended. Because of a parser bug, those versions also put IDs on some other nodes and missed some objects, and it was that output that was tested in-game. Files that already contain `_RefID`s are left untouched. Note that the developers' own numbering cannot be reproduced exactly: which classes get an ID depends on engine metadata not stored in the files.

## Widescreen Patch

The game renders at any resolution, but draws its 2D interface in a virtual 1024x768 space stretched to the screen. `warfront.py widescreen` (`widescreen.py`) generates a patch that keeps the interface in proportion:

- menus and dialogs are centred at 4:3
- the in-game HUD is anchored to the screen edges: minimap in the bottom-left corner, unit info in the bottom-right corner, command panel and top bar centred
- the top bar, the menu header and footer, dimming layers and the first-person scope overlay are widened to the full screen

The bottom HUD is a single image per faction, which the patch cuts into three pieces. Full-width decorations are widened by repeating plain parts of the original art. All images are built from the game's own files, so the patch contains no game art. The executable is not modified.

```bash
# Reads the resolution from Local Settings.setting, or pass -r 2560x1080
python3 warfront.py widescreen "C:/Games/War Front" -o widescreen_patch

# If the game's Inf folder is already patched, point at the originals
python3 warfront.py widescreen "C:/Games/War Front" --inf "C:/Games/War Front/Inf_backup" -o widescreen_patch
```

To install, back up `Inf`, copy the output folder's contents over the game folder, and set the virtual width the tool prints in `Local Settings.setting`:

```
stub\screensize\virtualsizex                       = num 1820
stub\screensize\virtualsizey                       = num 768
```

`virtualsizex` is `768 * width / height` (1365 for 16:9, 1229 for 16:10, 1820 for 2560x1080). The patch is built for one virtual width; rebuild it from the original files after changing the aspect ratio. `--text` writes text INF files instead of binary.

How the layout is rewritten (Prism UI rules found in the `Inf/2Prism` screens):

- A control's `c2DArea` is in screen coordinates when the control is top-level or has `Position = 1`, and relative to its parent when it has `Position = 0`
- A control's origin is its first area; a control without areas has its parent's origin. Primitive positions are relative to the origin
- Skin classes (`GERMAN`, `ALLIES`, `SOVIET`) override areas (`cPrismControlSkin`) and primitive geometry (`cPrism*Skin`, `TargetID = "control\primitive"`)
- Tooltips with `PosAbsolute = 1` have a screen-space `PosOffset`

The patch shifts only screen-space coordinates, so everything nested moves with its parent. Loading screens and the medal screens are painted artwork and stay 4:3.

## Editor Unlock and Debug Mode

`WarFront.exe` still contains Digital Reality's full level editor (window title *CoE*): level, terrain and trigger editing, the GUI editor, property windows for every game table, a render-debug panel and a **Debug Mode** switch. Start-up hard-codes the application mode to `"game"`, so the editor is never registered; pointing that one instruction at the existing `"editor"` string unlocks it.

```bash
# Retail or SP demo (Windows): patch in memory and start the editor
python3 warfront.py launch "C:/Games/War Front/WarFront.exe" --editor

# Normal game with Debug Mode on (relaxed tech/production checks for you in single-player)
python3 warfront.py launch "C:/Games/War Front/WarFront.exe" --debug-mode

# SP demo 1.01: write WarFront_editor.exe next to the original instead
python3 warfront.py patch-demo "C:/Games/War Front Demo/Run/WarFront.exe"
```

The retail exe is encrypted on disk, so `launch` waits until it has decrypted itself and patches it in memory before start-up reaches the patch site. It recognises the build by the original bytes (Hungarian retail and SP demo 1.01 are supported) and refuses unknown ones.

Good to know:

- The gameplay debug hotkeys (`D_GODMODE`, `D_EXTRAMONEY`, `D_FOWONOFF`, …) are compiled out of both builds and can't be enabled.
- The editor saves its state into the game folder and rewrites some `Inf` files (see the write-up). Back up `Inf` first.

Addresses, menus, the Debug Features panel and what Debug Mode changes are in [docs/editor-unlock.md](docs/editor-unlock.md).

---

## Binary INF Format

### Compressed File

```
Offset  Size  Description
------  ----  -----------
0x00    4     Magic (version)
0x04    4     Always 1
0x08    4     Uncompressed size
0x0C    ...   zlib stream (default compression level)
```

| Magic bytes | Version | String index width |
|-------------|---------|--------------------|
| `AA A5 FF FF` | 3 | 32-bit (almost every file) |
| `AB A5 FF FF` | 2 | 16-bit (`Gfx/Effects/me262.inf`) |
| `AC A5 FF FF` | 1 | recognised by the game, never seen |
| `AD A5 FF FF` | 0 | recognised by the game, never seen |

A few files (for example in the SP demo) are stored decompressed. They have no magic, so the tool identifies the version as the index width that parses the file exactly.

### Decompressed Data

Every file is a single tree:

```
Offset  Size  Description
------  ----  -----------
0x00    4     String table offset
0x04    4     Root property count
0x08    4     Root child node count
0x0C    ...   Root properties, then root child nodes
...           String table
...           Wide string table
```

The root has no name. Most files have no root properties and one child node, such as `PRGAME : cPRGame`. `terraintypetable.inf` has one root property (`StringID`), `defaultmusics.inf` has 23 top-level nodes, and `tdxdefs.inf` is 405 root properties and nothing else.

**Node** (all sections and objects share this layout):
```
name_idx      string index  e.g. "Controls *", ": cPrismButton", "ToolTip : cPrismToolTip"
prop_count    u32
child_count   u32
properties    prop_count × Property
children      child_count × Node
```

**Property:**
```
name_idx      string index
value_count   u8
values        value_count × (u8 type + data)
```

| Type | Data | Text form |
|------|------|-----------|
| 0 | string index | `"text"` |
| 1 | f64 | `1.5` |
| 2 | wide string index | `L"text"` |

A string index is u32 in version 3 and u16 in version 2.

**String table:** u32 count, then NUL-terminated strings. Strings are numbered in order of first use during a depth-first walk (node name, then each property's name and string values, then children). The same string is stored only once.

**Wide string table:** u32 count, then for each string a u32 UTF-16 code unit count followed by UTF-16LE data. Wide strings only appear in player profiles.

### Text Format

The text format is the one the game's developers wrote and the game reads directly:

```ini
StringID = ""

[PRGAME : cPRGame]
{
	_RefID = 1
	PublicEditor = 0
	EffectDataBase = "gfx\effects\coe_effects.fx"

	[Parameters : cPRGameParameters]
	{
		UseGrassColorMap = 0
		SelectionVolumeIncrementFactor = 2.5
	}
	[Controls *]
	{

		[: cPrismButton]
		{
			Name = "StartButton"
			Size = 1024, 112
		}
	}
}
```

- `[Name]` followed by `{ ... }` is a node. By convention, names ending in `*` are containers of `[: cClass]` objects, and `Name : cClass` is a named object.
- `Name = v1, v2, ...` is a property. Names may repeat.
- Strings are quoted and use no escape sequences (`"...\Grass\"` ends at the second `"`). Unquoted values are numbers if they look like one, otherwise strings (`Unit = axh_Hartman`).
- Lines starting with `;` are comments. CRLF line endings.
- `#define NAME value` lines are simple macros: from the definition on, `NAME` is replaced by `value` wherever it appears as a whole word outside quoted strings. Only two shipped files use them (`GlobalIncludes.inf` and `StateIcons.inf` in the sales preview).

---

## Reverse Engineering Notes

Earlier versions of the INF tool used three separate parsers, and needed a special "hybrid u16/u32" parser for `terraintypetable.inf`. Comparing more files showed these were all the same structure. The key observations were:

1. **The header fields at 0x04 and 0x08 are counts, not padding.** Normal files have `0, 1` (no root properties, one root node), `defaultmusics.inf` has `0, 23`, and `terraintypetable.inf` has `1, 1`. The bytes that looked like u16 fields in `terraintypetable.inf` (`01 00 01 00 00 00`) are a property record: value count 1, type 0, string index 1 (`""`).
2. **Sections and objects are one record type.** An empty container (`"Items *", 0, n`) and an object (`": cThing", props, children`) differ only in the name string. There is no separate "container marker".
3. **Unknown value types 5 and 7** (in `me262.inf` and `tdxdefs.inf`) came from misreading, not new types. `me262.inf` is version 2 with 16-bit indices, and `tdxdefs.inf` is a flat list of root properties.

Every structural claim above is checked by re-encoding: the unified parser consumes each of the 2,144 binary files in the retail, MP demo, SP demo and sales preview installs exactly up to its string table, and the re-encoded output equals the original.

Useful references in `WarFront.exe` found with Ghidra:

| Address | Purpose |
|---------|---------|
| `0x006a4610` | Magic value / version detection |
| `0x006a2e00` | Property reader |
| `0x006a4510` | Recursive node parser |

See [AGENTS.md](AGENTS.md) for how the format was first reverse engineered with Ghidra and Claude Code.

---

## Game Engine Details

### Prism Engine

WarFront uses the **Prism Engine** developed by Digital Reality. The INF files configure:

- **UI System** (`2Prism/*.inf`): Screen layouts, buttons, dialogs
- **Game Systems** (`*.inf`): Player profiles, campaigns, settings
- **Unit Definitions** (`bases/*.base`): Unit stats, abilities, models
- **Terrain** (`terrainmaps.inf`, `terraintypetable.inf`): Map properties

### Key Classes

| Class | Description |
|-------|-------------|
| `cPrismScreen` | Top-level screen/menu container |
| `cPrismControl` | Generic UI control |
| `cPrismButton` | Clickable button with states |
| `cPrismImagePrimitive` | Image/texture display |
| `cPrismTextPrimitive` | Text label rendering |
| `cTerrainTypeItem` | Terrain type properties |
| `cPlayerProfile` | Player save data |
| `cGameSystem` | Core game configuration |

### Common Properties

| Property | Type | Description |
|----------|------|-------------|
| `_RefID` | double | Object identifier (see [About `_RefID`](#about-_refid)) |
| `Name` | string | Object name for code reference |
| `Position` / `Pos` | double, double | X, Y position |
| `Size` | double, double | Width, height |
| `Color` | double × 4 | RGBA color (0-255 each) |

---

## The Sales Preview Build (May 2006)

The "Turning Point Sales Preview" (pre-beta, 2006-05-18, E3-era) is a developer build: its `Run/Inf` folder holds 1,127 `.inf`/`.base` files, **all in text form** (every one compiles with `-b`), and it ships folders the retail release doesn't have. Compared against the Hungarian retail release (`Inf_backup`, 1,099 files, almost all compressed binary):

### INF/BASE files

- 1,018 files exist in both. **Only two have identical content** (`2Prism/SkinInfo.inf` and `TerrainTypeTable.inf`); every other common file differs. Of the common files, 1,012 are text in the preview vs binary in retail, `baseinfos.inf`, `mplayer.inf` and `damagemultable.dat` are text in both, and `Physics/physics.phy` is binary in both.
- 121 files are preview-only, 81 retail-only (counts include the preview's zero-byte `!` marker files).

### Units (`Inf/bases`)

1,032 bases in the preview vs 1,016 in retail; the 966 shared ones all differ (typically a few lines: default properties such as `Color = 255, 255, 255, 255` that later versions write explicitly, plus renames and rebalancing — e.g. `al_m4_sherman.base` has `RequiredForSurvival` where retail has `RequiredForSurvivalSingleplayer`/`Multiplayer`, `ChaseRange = 50` where retail has `-1`, and an extra `cLampComponentBase`).

- Preview-only (68): units cut or renamed before release (`ge_brummbar`, `ge_flamethrower`, `ge_panzeriii`, `ge_tigerii`, `al_excelsior`, `al_jumbo`, `al_mk_iv_churchill`, `al_vickers_mk_vi`, `so_bt_5`, `so_kv2`, `so_su_152`, `so_t44`, `so_inv_communist_fever`, `mit_tigerii`), collision-test bases (`coll_test_*`), test props (`test*`, `st1`-`st3`), and extra grass/scenery variants.
- Retail-only (52): the `*_bunker_*` set, the `ambient_*` bases (a single `AmbientLocal.base` in the preview), `dam`, `campaign_*`, `conquer_flag`, attackable resource props, and others added later.

### UI screens (`Inf/2Prism`)

52 files in the preview vs 49 in retail. 41 exist in both, and all but `SkinInfo.inf` differ — some heavily (`centralpanel.inf`, the HUD, differs in ~9,400 lines; `gamescreen.inf` in ~12,000).

- Preview-only (12): the **E3 2006 demo screens** `e3mainmenu`, `e3effectdemo`, `e3rollingdemo`, `e3screenshots`, `e3backtomaindialog`, plus `singleplayerscreen`, `testscreen`, `exitgamedialog`, `replaydialog`, `replaystartdialog`, `medalvideoscreen`, `gamespygamesetup`.
- Retail-only (9): `cdkeyscreen`, `countdownscreen`, `cutscenescreen`, `exitdialog`, `exitscreen`, `gamespycreateaccount`, `versionscreen`, `workinganimdialog`, `workingdialog`.

### Root INF files

- Preview-only: `GlobalIncludes.inf` and `StateIcons.inf` (the two `#define` files), `NationalityTable.inf`, `SpeechOrder.inf`, `TileGroupModifier.inf`, `levels.inf` (weapon rank names), `managementorder.inf`, `maxvalues.inf`, `messages.inf`.
- Retail-only: `logsystem2.inf`, `tdxoptions.inf`, and a `game/` subfolder (`aicontent.inf`, `gamesettings.inf`, `nations.inf`, `schemacontent.inf`) — configuration that was reorganised for release.

### Levels

Preview: 24 multiplayer maps, 3 `Whoiswho` maps (`2vs2-autumn/-mediterran/-winter`), 11 Allied + 11 German campaign missions, 1 tutorial. Retail: 26 multiplayer maps (adds `3vs3map3 - Clash of Eagles` and `5vs5map3 - Battle Royale`), the whoiswho maps renamed to `Whoiswho - autumn/...`, the same 22 campaign missions, and a second tutorial (`tutorial_levelnew`). No common level is byte-identical. Notable preview extras: `E3 aim show.level` inside `2vs2map6 - Shortcuts`, and `mission6a`/`mission9_1` variants in the Allied campaign. The preview ships `.trg` trigger sources for every multiplayer map; retail ships them only for campaigns and adds `.desc` description files.

`.level` files are compressed INF files in both builds, but their properties use value type 3 (embedded blobs), which the INF tool does not parse (see Known Limitations).

### Preview-only folders

- `InfDX/` (847 files): the renderer's material/shader sources — 71 `.mat` material folders with `.tech`/`.pass` files, 225 `.hlsl` shaders, 17 `.layerset`, 30 `.surface`, and text `tdxdefs.inf`/`tdxoptions.inf` (the SP demo ships `tdxdefs.inf` as a decompressed binary). Comments are partly in Hungarian.
- `Editor/REffectEditor/` (19 files): models and textures for the effect editor.

### Root configuration files

- `Settings.setting` has an `e3demo` section (attract-mode timeouts and paths to `levels/E3B/...` demo levels, which are not in the build; `demomodeactiv = 0`). Retail instead has `gameengine\dontstorerefidsinbases = 1` — the switch behind the stripped `_RefID`s.
- `hotkeys.txt` was reworked between the builds (`GUARD = G` vs `GUARD_POS = G`, etc.); `keys.txt` and `useroptions.inf` are preview-only.
- The preview's `Run` folder also carries debug runtimes (`d3d9d.dll`, `d3dx9d_*.dll`, `MFC*D.DLL`, `MSVCRTD.DLL`) and developer utilities (`FlexGridSetup.exe`, `regcleaner.EXE`, `Amhooker.dll`).

---

## File Compatibility

Tested against the retail (Hungarian) release, MP demo, SP demo and sales preview:

| Files | Result |
|-------|--------|
| 2,140 compressed binaries (v3 and v2) | binary → text → binary is byte-identical |
| 4 decompressed binaries (SP demo profiles, `tdxdefs.inf`, `me262.inf`) | byte-identical |
| 2,270 developer-written text files | compile, and decompile back to the same tree |
| Retail `Inf` folder converted to text | game menus and missions work |

Run the byte-exact check against your own install with:

```bash
WARFRONT_DIR="/path/to/War Front" python3 -m unittest discover -s tests
```

Optional: `WARFRONT_INF_DIR` points the widescreen build test at the original `Inf` files if the game's own `Inf` folder is already patched, and `WARFRONT_DEMO_EXE` checks the editor patch against the SP demo 1.01 `WarFront.exe`.

### Known Limitations

- Byte-exact recompression needs a standard zlib build. Python builds that use zlib-ng instead, such as the official Windows builds of Python 3.14, compress differently: every retail file still round-trips to the same header and the same decompressed data, and the game loads it, but the compressed bytes differ and the byte-exact tests fail. Run those tests under WSL or Linux.

- Only object-like `#define NAME value` macros are expanded; other preprocessor directives (`#include`, `#ifdef`, ...) are rejected with an error. No shipped file uses them.
- `.level` map files are compressed INF files whose properties contain value type 3 (embedded blobs, e.g. compiled scripts); the parser does not support them. This applies to the retail release as well.
- Strings containing `"` or line breaks can't be written as text (none exist in any shipped file).
- Magic versions 0 and 1 are not supported; no files using them are known.
- `IntroDesc.inf` is a bare movie path, not an INF, and is skipped.

---

## Developer Tools

### bc.exe - Binary Converter

The game's development files include references to `bc.exe`, a tool used by Digital Reality developers to convert between text and binary INF formats. Evidence of this tool can be found in `converttobinary.bat` files scattered throughout the game directories:

```batch
# Example from Inf/bases/converttobinary.bat
bc "al_m4_sherman.base" B
bc "ge_tiger.base" B
bc "so_t34.base" B
...
del *.bak
```

The `B` argument likely specifies "convert to Binary" mode. The tool also appears to create `.bak` backup files during conversion. Unfortunately, `bc.exe` itself is not included in any known game distribution and was likely an internal development tool.

This confirms that:
1. Digital Reality developed and used text INF files during development
2. Binary conversion was done as a build/release step
3. A reverse tool (binary-to-text) may have also existed

`warfront.py inf -b` does the same job as `bc ... B`: its output for shipped files is identical to what `bc.exe` produced.

---

## Contributing

Contributions welcome! Areas of interest:

- [ ] GUI editor for INF files
- [x] `#define` macro expansion for developer text files
- [ ] `#include` preprocessing for developer text files
- [ ] Compatibility with other Digital Reality games
- [ ] Editor patch addresses for more builds (MP demo, sales preview, other languages)
- [ ] Play-test and document exactly what Debug Mode unlocks

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Digital Reality for creating WarFront: Turning Point
- The Ghidra project for the reverse engineering framework
- The modding community for preserving classic games
