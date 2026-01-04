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
git clone https://github.com/balcsida/warfront-inf-tools.git
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

## Enabling Text INF in Game

To make the game read text INF files instead of binary:

1. Edit `Settings.setting` in the game's Run folder
2. Set `binaryinffiles = 0`
3. Replace binary INF files with converted text versions

---

## Binary INF Format Documentation

The game uses three distinct binary INF formats, each serving different purposes.

### Compressed File Header

All binary INF files are zlib-compressed with a 12-byte header:

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

---

## Format 1: Object Format (BinaryInfParser)

Used by most game files including `game.inf`, UI screens (`2Prism/*.inf`), and base files (`bases/*.base`).

### Decompressed Structure

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

**Root Object** (class name from strings[0]):
```
prop_count:    4 bytes (u32)
child_count:   4 bytes (u32)
properties:    variable
sections:      variable
```

**Child Object** (inside container sections):
```
class_idx:     4 bytes (u32, index into string table)
prop_count:    4 bytes (u32)
child_count:   4 bytes (u32)
properties:    variable
sections:      variable
```

### Property Format

```
name_idx:  4 bytes (u32, index into string table)
count:     1 byte (u8, number of values)
type:      1 byte (u8, first value type)
values:    variable (count × value entries)

For values after the first:
  type:    1 byte (u8)
  value:   variable
```

**Property Types:**
| Type | Size | Description |
|------|------|-------------|
| 0 | 4 bytes | String index (u32) |
| 1 | 8 bytes | Double (IEEE 754 float64) |
| 2 | 4 bytes | Wide string index (u32) |
| 3 | 4+n bytes | Blob (u32 length + raw data) |

### Section Format

Two section variants:

**1. Container Section** (second field = 0):
```
name_idx:    4 bytes (e.g., "Controls *")
zero:        4 bytes (always 0)
obj_count:   4 bytes (number of child objects)
objects:     variable (obj_count × child objects)
```

**2. Inline Object Section** (second field ≠ 0):
```
name_idx:    4 bytes (e.g., "ToolTip : cPrismToolTip")
prop_count:  4 bytes (non-zero)
child_count: 4 bytes
properties:  variable
sections:    variable
```

### Text Output Example

```ini
[: cPrismScreen]
{
    _RefID = 1
    Name = "MainMenu"
    Position = 0, 656
    Size = 1024, 112

    [Controls *]
    {
        [: cPrismButton]
        {
            _RefID = 2
            Name = "StartButton"
        }
    }
}
```

---

## Format 2: Simple Format (SimpleInfParser)

Used by configuration files like `terrainmaps.inf` and `defaultmusics.inf`. Features flat or nested sections without `_RefID` values.

### Header Structure

```
Offset  Size  Description
------  ----  -----------
0x00    4     String table offset
0x04    4     Reserved
0x08    4     Section count (> 1 indicates simple format)
0x0C    4     Reserved
0x10    ...   Section data
```

### Section Format

Each section:
```
prop_count:   4 bytes (u32)
child_count:  4 bytes (u32)
properties:   variable
child sections: recursive
```

For sections after the first:
```
name_idx:     4 bytes (u32, before prop_count)
prop_count:   4 bytes
child_count:  4 bytes
...
```

### Property Format

```
name_idx:    4 bytes (u32)
val_count:   1 byte (u8)
val_type:    1 byte (u8)
values:      variable

For subsequent values:
  val_type:  1 byte (u8)
  value:     variable
```

### Text Output Example

```ini
[TerrainMaps]
{
    type=WordMap

    [Water]
    {
        [Values]
        {
            [Off]
            {
                file=terrain/WaterHeight.tga
            }
            [On]
            {
                file=terrain/WaterHeight.tga
            }
        }
    }
}
```

**Key Differences from Object Format:**
- No `_RefID` values
- No spaces around `=` in properties
- Nested sections using `child_count` field
- Multiple top-level sections allowed

---

## Format 3: TerrainTypeTable Format (TerrainTypeTableParser)

A hybrid format unique to `terraintypetable.inf` that combines u16 root header with u32 child objects.

### Header Structure

```
Offset  Size  Description
------  ----  -----------
0x00    4     String table offset
0x04    4     Version flag (= 1)
0x08    4     Reserved (= 1)
0x0C    4     Reserved (= 0)
0x10    ...   Root data (u16 format)
0x22    ...   Child objects (u32 format)
```

### Root Section (u16 format)

```
Offset  Size  Description
------  ----  -----------
0x10    2     prop_count (u16)
0x12    2     sec_count (u16)
0x14    2     prop_name_idx (u16)
0x16    2     sec_name_idx (u16)
0x18    4     prop_value (u32, 0 = empty)
0x1C    2     padding (u16)
0x1E    2     child_count (u16)
0x20    2     padding (u16)
0x22    ...   First child object
```

### Child Objects (Standard u32 format)

From offset 0x22 onwards, child objects use the standard u32 format:
```
class_idx:    4 bytes (u32)
prop_count:   4 bytes (u32)
sec_count:    4 bytes (u32)
properties:   standard format
sections:     standard format
```

### Text Output Example

```ini
StringID = ""

[TerrainTypes *]
{

    [: cTerrainTypeItem]
    {
        Name = "#0;0 - Human"
        SpeedMultiplier = 1
        TrackColorMultiplier = 255, 255, 255, 255

        [EffectModifierTable *]
        {
        }
    }
}
```

---

## Reverse Engineering Methodology

The binary formats were reverse engineered using a combination of Ghidra analysis and comparison with reference text files from the sales preview version of the game.

### Step 1: Identify Reference Files

The sales preview version (`salespreview/Run/Inf/`) contains some INF files already in text format, providing ground truth for the expected output:

```bash
# Example: TerrainTypeTable.inf in sales preview is text format
cat salespreview/Run/Inf/TerrainTypeTable.inf
```

```ini
StringID = ""

[TerrainTypes *]
{
    [: cTerrainTypeItem]
    {
        Name = "#0;0 - Human"
        SpeedMultiplier = 1
        TrackColorMultiplier = 255, 255, 255, 255
        ...
    }
}
```

### Step 2: Decompress and Hex Dump Binary Files

```bash
# Decompress the binary version
python decompress_inf.py -a retail/Inf/terraintypetable.inf

# Hex dump for analysis
xxd terraintypetable_decompressed.inf | head -40
```

Output:
```
00000000: 4e04 0000 0100 0000 0100 0000 0000 0000  N...............
00000010: 0100 0100 0000 0200 0000 0000 0000 0c00  ................
00000020: 0000 0300 0000 0300 0000 0100 0000 0400  ................
...
```

### Step 3: Locate String Table

The first 4 bytes contain the string table offset:

```python
import struct
sto = struct.unpack('<I', data[0:4])[0]  # 0x44E = 1102
```

Parse strings at that offset:
```python
pos = sto + 4  # Skip string count
strings = []
for i in range(str_count):
    end = data.find(b'\x00', pos)
    strings.append(data[pos:end].decode('utf-8'))
    pos = end + 1

# Result:
# [0] = 'StringID'
# [1] = ''
# [2] = 'TerrainTypes *'
# [3] = ': cTerrainTypeItem'
# [4] = 'Name'
# [5] = '#0;0 - Human'
# ...
```

### Step 4: Find Known Patterns in Binary

Search for patterns that match expected structure:

```python
# Search for child object pattern: class_idx=3, prop_count=3, sec_count=1
pattern = bytes([0x03, 0x00, 0x00, 0x00,  # class_idx = 3
                 0x03, 0x00, 0x00, 0x00,  # prop_count = 3
                 0x01, 0x00, 0x00, 0x00]) # sec_count = 1

idx = data.find(pattern)
# Found at offset 0x22!
```

### Step 5: Trace Back to Root Structure

Knowing child objects start at 0x22, analyze bytes 0x10-0x21:

```
0x10: 01 00  ->  prop_count = 1 (u16)
0x12: 01 00  ->  sec_count = 1 (u16)
0x14: 00 00  ->  prop_name_idx = 0 (u16) = "StringID"
0x16: 02 00  ->  sec_name_idx = 2 (u16) = "TerrainTypes *"
0x18: 00 00 00 00  ->  prop_value = 0 (empty)
0x1C: 00 00  ->  padding
0x1E: 0C 00  ->  child_count = 12 (u16)
0x20: 00 00  ->  padding
```

This revealed the hybrid u16/u32 format unique to terraintypetable.inf.

### Step 6: Validate with Ghidra

Key addresses in WarFront.exe found via Ghidra:

| Address | Content | Purpose |
|---------|---------|---------|
| `0x007EEF10` | `"inf/TerrainTypeTable.inf"` | File path string |
| `0x00828CF0` | `"cTerrainType"` | Class name |
| `0x00828E10` | `"TerrainTypes"` | Section name |
| `0x006a4610` | Function | Magic value detection |
| `0x006a2e00` | Function | Property reader |
| `0x006a4510` | Function | Recursive object parser |

### Step 7: Verify Double Values

IEEE 754 double patterns helped identify value types:

```python
# 1.0 in IEEE 754 = 0x3FF0000000000000
one = struct.pack('<d', 1.0)  # 00 00 00 00 00 00 f0 3f

# Search for 1.0 in file
idx = data.find(one)  # Found at 0x3E - SpeedMultiplier value

# 255.0 in IEEE 754 = 0x406FE00000000000
twofiftyfive = struct.pack('<d', 255.0)  # 00 00 00 00 00 e0 6f 40

# Found at 0x4C, 0x55, 0x5E, 0x67 - TrackColorMultiplier values
```

### Step 8: Build and Test Parser

Implement parser based on discovered structure, then validate:

```bash
# Convert binary to text
python decompress_inf.py -t -f terraintypetable.inf output.inf

# Compare with reference
diff output.inf salespreview/Run/Inf/TerrainTypeTable.inf
```

### Format Detection Logic

The parser automatically detects which format to use:

```python
def binary_to_text(data):
    if is_terraintypetable_format(data):
        # Header: 01 00 00 00 01 00 00 00 00 00 00 00 at 0x04
        # First string is 'StringID'
        parser = TerrainTypeTableParser(data)
    elif is_simple_format(data):
        # Section count > 1 at offset 0x08
        # No child objects at offset 0x14
        parser = SimpleInfParser(data)
    else:
        # Standard object format with _RefID
        parser = BinaryInfParser(data)
    return parser.parse()
```

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
| `_RefID` | double | Unique object identifier (object format only) |
| `Name` | string | Object name for code reference |
| `Position` / `Pos` | double, double | X, Y position |
| `Size` | double, double | Width, height |
| `Color` | double × 4 | RGBA color (0-255 each) |

---

## File Compatibility

### Successfully Tested Files

| Directory | Count | Notes |
|-----------|-------|-------|
| `Inf/*.inf` | ~10 | Including terraintypetable.inf |
| `Inf/2Prism/*.inf` | 49 | UI screens |
| `Inf/Fonts/*.inf` | 15 | Font definitions |
| `Inf/game/*.inf` | 4 | Game configurations |
| `Inf/bases/*.base` | 1016 | Unit definitions |

### Known Limitations

- `terraintypetable.inf` uses a hybrid format requiring special parser
- Some files may have game-version-specific differences
- Wide string (UTF-16) support is basic
- `mplayer.inf` uses a different format (starts with "SERV" magic) and is not supported

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

---

## Contributing

Contributions welcome! Areas of interest:

- [ ] Text-to-binary converter (recompile edited files) - could replicate `bc.exe` functionality
- [ ] GUI editor for INF files
- [ ] Additional game format documentation
- [ ] Compatibility with other Digital Reality games

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Digital Reality for creating WarFront: Turning Point
- The Ghidra project for the reverse engineering framework
- The modding community for preserving classic games
