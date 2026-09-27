# Reverse Engineering Methodology

This document describes how the WarFront INF binary format was reverse engineered using Ghidra and Claude Code with MCP (Model Context Protocol) integration.

## Tools Used

- **Ghidra SRE**: NSA's Software Reverse Engineering framework
- **GhydraMCP**: MCP server for Ghidra integration with Claude
- **Claude Code**: AI-assisted code analysis and generation

## Reverse Engineering Process

### Phase 1: Initial Analysis

The investigation started with examining sample INF files to identify patterns:

```bash
xxd Inf/2Prism/mainmenu.inf | head -5
# 00000000: aaa5 ffff 0100 0000 7d28 0000 789c...
```

**Observations:**
- Files start with `AA A5 FF FF` (little-endian: 0xFFFFA5AA)
- Followed by size values
- zlib magic `78 9c` indicates compression

### Phase 2: Ghidra Analysis via MCP

Using GhydraMCP, we connected Claude directly to a running Ghidra instance analyzing the game executable:

```python
# List functions related to INF parsing
mcp__ghydra__functions_list(name_contains="inf")

# Decompile the magic detection function
mcp__ghydra__functions_decompile(address="0x006a4610")
```

#### Key Functions Discovered

**1. Magic Value Detection (0x006a4610)**

```c
int detect_version(byte *magic) {
    if (*(uint *)magic == 0xFFFFA5AA) return 3;  // Version 3
    if (*(uint *)magic == 0xFFFFA5AB) return 2;  // Version 2
    if (*(uint *)magic == 0xFFFFA5AC) return 1;  // Version 1
    if (*(uint *)magic == 0xFFFFA5AD) return 0;  // Version 0
    return -1;  // Not compressed binary
}
```

**2. Property Reader (0x006a2e00)**

```c
void read_property(stream *s, object *obj) {
    uint name_idx = read_u32(s);
    byte count = read_u8(s);

    for (int i = 0; i < count; i++) {
        byte type = read_u8(s);
        switch (type) {
            case 0:  // String
                uint str_idx = read_u32(s);
                break;
            case 1:  // Double
                double val = read_f64(s);
                break;
            case 2:  // Wide string
                uint wstr_idx = read_u32(s);
                break;
            case 3:  // Blob
                uint len = read_u32(s);
                skip_bytes(s, len);
                break;
        }
    }
}
```

**3. Object Parser (0x006a4510)**

Analysis revealed the recursive structure:
- Objects contain properties and child sections
- Sections contain child objects
- Two section formats: container vs inline

### Phase 3: Format Discovery Challenges

Several incorrect assumptions were made and corrected:

#### Challenge 1: Property Type Location

**Initial (Wrong):**
```
name_idx(4) + type(2) + count(1) + values...
```

**Correct:**
```
name_idx(4) + count(1) + [type(1) + value]×count
```

Each value has its own type byte, not a shared type for all values.

#### Challenge 2: Object Header Structure

**Initial (Wrong):**
```
class_idx(4) + prop_count(4) + child_count(4)  # For all objects
```

**Correct:**
- Root object: `prop_count(4) + child_count(4)` (class is strings[0])
- Child objects: `class_idx(4) + prop_count(4) + child_count(4)`

#### Challenge 3: Section Format Variants

Discovery that sections have two distinct formats:

**Container Section (type = 0):**
```
name_idx(4) + 0(4) + obj_count(4) + objects...
```

**Inline Object Section (type != 0):**
```
name_idx(4) + prop_count(4) + child_count(4) + properties + sections
```

The class name is embedded in the section name after " : " (e.g., "ToolTip : cPrismToolTip").

### Phase 4: Iterative Validation

Each format discovery was validated by:

1. Parsing sample files with the new understanding
2. Comparing output with expected string values
3. Tracing through the parser step-by-step
4. Fixing misalignments until full files parsed correctly

```python
# Example validation trace
pos = 0x10
prop_count = u32(pos)      # 8 properties
child_count = u32(pos+4)   # 5 sections

# Parse each property and verify names match expectations
for i in range(prop_count):
    name_idx = u32(pos)
    assert strings[name_idx] in expected_properties
    # ...
```

## Claude Code Workflow

### MCP Integration Benefits

The GhydraMCP integration allowed:

1. **Direct function decompilation**: Query Ghidra for decompiled C code
2. **Cross-reference analysis**: Find where functions are called
3. **Memory inspection**: Read data at specific addresses
4. **String analysis**: List all strings in the binary

### Iterative Development Pattern

```
1. Hypothesize format structure
2. Implement parser
3. Test on sample files
4. Analyze errors (wrong values, parse failures)
5. Use Ghidra to verify assumptions
6. Correct understanding
7. Repeat until all files parse correctly
```

### Key Debugging Techniques

**Hex Dump Comparison:**
```python
# Compare expected vs actual parsing position
print(f'Expected at 0x{expected:x}, actual at 0x{parser.pos:x}')
```

**Property Tracing:**
```python
# Log each property as parsed
print(f'Property {i}: {strings[name_idx]} = {values}')
```

**Format Visualization:**
```python
# Show raw bytes at current position
for i in range(pos, pos+16):
    print(f'0x{i:x}: 0x{data[i]:02x}')
```

## Lessons Learned

### 1. Don't Trust Initial Assumptions

The first interpretation of the format is often wrong. Binary formats frequently have subtle variations based on context (e.g., root vs child objects).

### 2. Validate Incrementally

Parse small portions first, validate they're correct, then expand. Don't try to parse entire complex files before validating basic structures.

### 3. Use Multiple Sample Files

Some format features only appear in certain files. Testing against multiple samples reveals the full format specification.

### 4. Ghidra + AI = Powerful Combination

The ability to query decompiled code while simultaneously writing parsers dramatically accelerates reverse engineering.

## Later Findings

### Text-to-Binary Converter (done)

`decompress_inf.py -b` compiles text back to binary. Building it forced every
format assumption to be checked by re-encoding: the output must equal the
original file byte for byte. That check exposed three mistakes in the earlier
analysis, all fixed now:

- The 12-byte compressed header is `magic, 1, uncompressed_size`, not
  `magic, compressed_size, uncompressed_size`.
- The "reserved" words at 0x04/0x08 of the decompressed data are the root
  property and child counts. "Root object", "simple format" and the
  `terraintypetable.inf` "u16 hybrid" are all the same structure.
- Containers and inline sections are the same node record; only the name
  string differs. Version 2 files (`me262.inf`) use 16-bit string indices.

### Lesson: Verify by Round-Tripping

A parser that produces plausible output can still be wrong. Re-encoding the
parsed tree and comparing bytes with the original shows every misunderstanding
immediately.

### Additional Formats

Other game files may use similar formats:
- Save game files
- Mission configuration

## References

- [Ghidra Project](https://ghidra-sre.org/)
- [GhydraMCP](https://github.com/example/ghydra-mcp) - Ghidra MCP Server
- [Claude Code](https://claude.ai/claude-code) - AI coding assistant

## Appendix: Complete Format Specification

See the "Binary INF Format" section of [README.md](README.md), which is kept
in sync with the implementation in `decompress_inf.py`.
