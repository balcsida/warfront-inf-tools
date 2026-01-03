# WarFront: Turning Point - INF File Tools

Reverse engineering tools for the binary INF configuration files used by **WarFront: Turning Point** (2007 RTS game by Digital Reality).

## Overview

WarFront uses a custom binary INF format for storing game configuration, UI layouts, player profiles, and other data. This repository provides tools to:

- **Decompress** zlib-compressed INF files
- **Convert** binary INF to human-readable text format
- **Analyze** INF file structure

The game engine supports both binary and text INF formats, allowing modders to edit configuration files after conversion.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/warfront-inf-tools.git
cd warfront-inf-tools

# No dependencies required beyond Python 3.6+
python3 decompress_inf.py --help
```

## Usage

### Convert All INF Files to Text

```bash
# Default: Process Inf/ folder -> Inf_text/
python3 decompress_inf.py -t

# Custom input/output directories
python3 decompress_inf.py -t -d "Game/Data/Inf" "Output/Inf"

# Convert in place (overwrites original files)
python3 decompress_inf.py -t -i "Game/Data/Inf"
```

### Convert Single File

```bash
python3 decompress_inf.py -t -f input.inf output.inf
```

### Decompress Only (Keep Binary Format)

```bash
# Without -t flag, outputs decompressed binary
python3 decompress_inf.py -d Inf Inf_decompressed
```

### Analyze File Structure

```bash
python3 decompress_inf.py -a file.inf
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --to-text` | Convert binary INF to human-readable text format |
| `-d INPUT OUTPUT` | Process directory INPUT to OUTPUT |
| `-i DIR` | Process files in place (modify original directory) |
| `-f INPUT OUTPUT` | Process single file |
| `-a FILE` | Analyze file without writing output |
| `-v, --verbose` | Show detailed output during processing |

## File Format Documentation

### Compressed INF Format

INF files are typically zlib-compressed with a 12-byte header:

```
Offset  Size  Description
------  ----  -----------
0x00    4     Magic value (version identifier)
0x04    4     Compressed size (little-endian)
0x08    4     Uncompressed size (little-endian)
0x0C    ...   zlib compressed data
```

**Magic Values:**
| Bytes (LE) | Value | Version |
|------------|-------|---------|
| `AA A5 FF FF` | 0xFFFFA5AA | 3 (newest) |
| `AB A5 FF FF` | 0xFFFFA5AB | 2 |
| `AC A5 FF FF` | 0xFFFFA5AC | 1 |
| `AD A5 FF FF` | 0xFFFFA5AD | 0 |

### Decompressed Binary Format

```
Offset  Size  Description
------  ----  -----------
0x00    4     String table offset
0x04    12    Reserved/padding (zeros)
0x10    ...   Root object data
...     ...   String table (at offset specified in header)
...     ...   Wide string table (UTF-16LE)
```

### Object Structure

**Root Object** (class name is strings[0]):
```
prop_count:    4 bytes (number of properties)
child_count:   4 bytes (number of child sections)
properties:    variable (see Property Format)
sections:      variable (see Section Format)
```

**Child Object** (inside container sections):
```
class_idx:     4 bytes (index into string table)
prop_count:    4 bytes
child_count:   4 bytes
properties:    variable
sections:      variable
```

### Property Format

```
name_idx:  4 bytes (index into string table)
count:     1 byte (number of values)
values:    variable (count × value entries)

Value entry:
  type:    1 byte
  value:   variable (depends on type)
```

**Property Types:**
| Type | Size | Description |
|------|------|-------------|
| 0 | 4 bytes | String index (into string table) |
| 1 | 8 bytes | Double (IEEE 754 float64) |
| 2 | 4 bytes | Wide string index (into wide string table) |
| 3 | 4+n bytes | Blob (4-byte length + raw data) |

### Section Format

Two section variants exist:

**1. Container Section** (holds multiple child objects):
```
name_idx:      4 bytes (e.g., "Controls *")
type:          4 bytes (always 0)
obj_count:     4 bytes (number of child objects)
objects:       variable (obj_count × child objects)
```

**2. Inline Object Section** (properties embedded, class in name):
```
name_idx:      4 bytes (e.g., "ToolTip : cPrismToolTip")
prop_count:    4 bytes (non-zero, distinguishes from container)
child_count:   4 bytes
properties:    variable
sections:      variable
```

The class name is extracted from the section name after " : " (e.g., "ToolTip : cPrismToolTip" → class is ": cPrismToolTip").

### String Table

Located at the offset specified in the file header:

```
count:     4 bytes (number of strings)
strings:   variable (null-terminated UTF-8 strings)
```

### Wide String Table

Follows the regular string table:

```
count:     4 bytes (number of wide strings)
entries:   variable

Entry format:
  char_count:  4 bytes (number of UTF-16 code units)
  data:        char_count × 2 bytes (UTF-16LE encoded)
```

## Text Output Format

Converted files use an INI-like text format:

```ini
[: cPrismScreen]
{
    _RefID = 1
    StringID =
    Name = MainMenu
    Skinnable = 0
    Position = 0, 656
    Size = 1024, 112
    Color = 255, 255, 255, 255
    PlayerNameW = L"Player"

    Controls *
    [: cPrismControl]
    {
        _RefID = 2
        Name = button1
        ...
    }

    ToolTip
    [: cPrismToolTip]
    {
        _RefID = 3
        ...
    }
}
```

**Format Rules:**
- Class names in brackets: `[: ClassName]`
- Properties as `name = value` or `name = val1, val2, ...`
- Wide strings prefixed with `L"..."`
- Sections listed by name, followed by child objects
- Nested objects indented with tabs

## Game Engine Details

### Prism Engine

WarFront uses the **Prism Engine** developed by Digital Reality. The INF files configure:

- **UI System** (`2Prism/*.inf`): Screen layouts, buttons, dialogs
- **Game Systems** (`*.inf`): Player profiles, campaigns, settings
- **Resources**: Texture paths, fonts, sounds

### Key Classes

| Class | Description |
|-------|-------------|
| `cPrismScreen` | Top-level screen/menu container |
| `cPrismControl` | Generic UI control (buttons, panels) |
| `cPrismButton` | Clickable button with states |
| `cPrismImagePrimitive` | Image/texture display |
| `cPrismTextPrimitive` | Text label rendering |
| `cPrismVideoPrimitive` | Video playback control |
| `cPrismToolTip` | Hover tooltip configuration |
| `cPrismHotkeySlot` | Keyboard shortcut binding |
| `cPlayerProfile` | Player save data |
| `cGameSystem` | Core game configuration |

### Common Properties

| Property | Type | Description |
|----------|------|-------------|
| `_RefID` | double | Unique object identifier |
| `Name` | string | Object name for code reference |
| `Pos` | double, double | X, Y position |
| `Size` | double, double | Width, height |
| `Color` | double × 4 | RGBA color (0-255 each) |
| `Cursor` | string | Mouse cursor type |
| `TemplateName` | string | Reference to template object |

## Reverse Engineering Notes

The binary format was reverse engineered using Ghidra. Key functions analyzed:

- `0x006a4610`: Magic value detection and version parsing
- `0x006a2e00`: Property reader (handles all 4 types)
- `0x006a4510`: Recursive object parser

See [AGENTS.md](AGENTS.md) for the full reverse engineering methodology.

## Contributing

Contributions welcome! Areas of interest:

- [ ] Text-to-binary converter (recompile edited files)
- [ ] GUI editor for INF files
- [ ] Additional game format documentation
- [ ] Compatibility with other Digital Reality games

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Digital Reality for creating WarFront: Turning Point
- The Ghidra project for the reverse engineering framework
- The modding community for preserving classic games
