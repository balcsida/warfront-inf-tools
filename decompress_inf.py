"""
WarFront: Turning Point INF File Decompressor & Converter

Binary INF Format (from Ghidra RE analysis at 0x006a4610):

COMPRESSED FILE FORMAT (12-byte header):
- Bytes 0-3: Magic (version identifier)
  - 0xFFFFA5AA (AA A5 FF FF) = version 3 (newest)
  - 0xFFFFA5AB = version 2
  - 0xFFFFA5AC = version 1
  - 0xFFFFA5AD = version 0
- Bytes 4-7: Compressed size (little-endian)
- Bytes 8-11: Uncompressed size (little-endian)
- Bytes 12+: zlib compressed data

DECOMPRESSED BINARY FORMAT:
- Bytes 0-3: String table offset
- Bytes 4-15: Reserved/padding (zeros)
- Bytes 16+: Root object (prop_count + child_count + properties + sections)
- String table at offset: 4-byte count + null-terminated UTF-8 strings
- Wide string table after strings: 4-byte count + (char_count + UTF-16LE data) per string

ROOT OBJECT FORMAT (class name is strings[0]):
- prop_count: 4 bytes
- child_count: 4 bytes
- properties: see property format
- child_sections: see section format

CHILD OBJECT FORMAT (inside container sections):
- class_idx: 4 bytes (index into string table)
- prop_count: 4 bytes
- child_count: 4 bytes
- properties
- child_sections

PROPERTY FORMAT:
- name_idx: 4 bytes (index into string table)
- count: 1 byte (number of values)
- For each value:
  - type: 1 byte (0=string_idx, 1=double, 2=wstring_idx, 3=blob)
  - value: 4 bytes (string/wstring idx), 8 bytes (double), or 4+n bytes (blob length + data)

SECTION FORMAT (two variants):
1. Container section (second_field = 0):
   - name_idx: 4 bytes (e.g., "Controls *")
   - 0: 4 bytes
   - obj_count: 4 bytes
   - child objects (each has class_idx)

2. Inline object section (second_field != 0, name contains " : "):
   - name_idx: 4 bytes (e.g., "ToolTip : cPrismToolTip")
   - prop_count: 4 bytes
   - child_count: 4 bytes
   - properties
   - child_sections
"""

import zlib
import os
import glob
import struct
import argparse

# Magic values for binary INF versions (from Ghidra analysis at 0x006a4610)
MAGICS = {
    b'\xAA\xA5\xFF\xFF': 3,  # Version 3 (0xFFFFA5AA in LE)
    b'\xAB\xA5\xFF\xFF': 2,  # Version 2
    b'\xAC\xA5\xFF\xFF': 1,  # Version 1
    b'\xAD\xA5\xFF\xFF': 0,  # Version 0
}

def get_version(magic_bytes):
    """Get version number from magic bytes."""
    return MAGICS.get(magic_bytes, None)


class BinaryInfParser:
    """Parser for decompressed binary INF files - converts to text format."""

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.strings = []
        self.wstrings = []
        self.refid_counter = 0  # Counter for generating _RefID values
        self._load_string_tables()

    def next_refid(self):
        """Get next _RefID value and increment counter."""
        self.refid_counter += 1
        return self.refid_counter

    def _load_string_tables(self):
        """Load string and wide string tables from the end of the file."""
        sto = struct.unpack('<I', self.data[0:4])[0]
        if sto < 16 or sto >= len(self.data):
            raise ValueError(f"Invalid string table offset: {sto}")

        pos = sto

        # Read regular strings
        str_count = struct.unpack('<I', self.data[pos:pos+4])[0]
        pos += 4

        for _ in range(str_count):
            end = self.data.find(b'\x00', pos)
            if end == -1:
                break
            self.strings.append(self.data[pos:end].decode('utf-8', errors='replace'))
            pos = end + 1

        # Read wide strings (UTF-16LE)
        if pos + 8 <= len(self.data):
            wstr_count = struct.unpack('<I', self.data[pos:pos+4])[0]
            pos += 4

            for _ in range(wstr_count):
                if pos + 4 > len(self.data):
                    break
                char_count = struct.unpack('<I', self.data[pos:pos+4])[0]
                pos += 4
                byte_len = char_count * 2
                if pos + byte_len > len(self.data):
                    break
                try:
                    self.wstrings.append(self.data[pos:pos+byte_len].decode('utf-16le'))
                except:
                    self.wstrings.append(f'<wstring@{pos}>')
                pos += byte_len

    def u8(self):
        val = self.data[self.pos]
        self.pos += 1
        return val

    def u32(self):
        val = struct.unpack('<I', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return val

    def f64(self):
        val = struct.unpack('<d', self.data[self.pos:self.pos+8])[0]
        self.pos += 8
        return val

    def get_str(self, idx):
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return f'<string_{idx}>'

    def get_wstr(self, idx):
        if 0 <= idx < len(self.wstrings):
            return self.wstrings[idx]
        return f'<wstring_{idx}>'

    def fmt_double(self, v):
        """Format double value, showing integers without decimals."""
        if v == int(v) and abs(v) < 1e15:
            return str(int(v))
        return str(v)

    def needs_quotes(self, s):
        """Check if a string value needs quotes in the output."""
        # Empty strings always need quotes
        if not s:
            return True
        # Strings with spaces, special chars, or paths need quotes
        if ' ' in s or '/' in s or '\\' in s or '"' in s or '=' in s:
            return True
        # Strings that look like file paths need quotes
        if '.' in s and '/' not in s and '\\' not in s:
            # Could be a file extension like "times_8_normal" - check if it has path-like chars
            pass
        return True  # Quote all strings for safety

    def fmt_string(self, s):
        """Format a string value with quotes if needed."""
        if self.needs_quotes(s):
            # Escape any quotes in the string
            s = s.replace('"', '\\"')
            return f'"{s}"'
        return s

    def parse_property(self):
        """Parse a single property and return as text line.

        Returns None if the property should be skipped (e.g., _RefID which we generate ourselves).
        """
        name_idx = self.u32()
        prop_name = self.get_str(name_idx)
        count = self.u8()

        vals = []
        for _ in range(count):
            ptype = self.u8()
            if ptype == 0:  # String index
                idx = self.u32()
                vals.append(self.fmt_string(self.get_str(idx)))
            elif ptype == 1:  # Double
                vals.append(self.fmt_double(self.f64()))
            elif ptype == 2:  # Wide string index
                idx = self.u32()
                vals.append(f'L"{self.get_wstr(idx)}"')
            elif ptype == 3:  # Blob
                blob_len = self.u32()
                self.pos += blob_len
                vals.append(f'<blob:{blob_len}>')
            else:
                raise ValueError(f'Unknown property type {ptype} at 0x{self.pos-1:X}')

        # Skip _RefID properties - we generate these ourselves with proper sequential numbering
        if prop_name == '_RefID':
            return None

        return f'{prop_name} = {", ".join(vals)}'

    def parse_root_object(self, indent=0):
        """Parse the root object (no class_idx, uses strings[0])."""
        lines = []
        ind = '\t' * indent

        prop_count = self.u32()
        child_count = self.u32()
        class_name = self.get_str(0)  # Root uses strings[0]

        lines.append(f'{ind}[{class_name}]')
        lines.append(f'{ind}{{')

        # Add _RefID as first property
        lines.append(f'{ind}\t_RefID = {self.next_refid()}')

        # Parse properties
        for _ in range(prop_count):
            prop_line = self.parse_property()
            if prop_line is not None:  # Skip None (filtered properties like _RefID)
                lines.append(f'{ind}\t{prop_line}')

        # Add blank line after properties, before child sections
        if prop_count > 0 or child_count > 0:
            lines.append('')

        # Parse child sections
        for _ in range(child_count):
            section_lines = self.parse_section(indent + 1)
            lines.extend(section_lines)

        lines.append(f'{ind}}}')
        return lines

    def parse_child_object(self, indent=0):
        """Parse a child object (has class_idx as first field)."""
        lines = []
        ind = '\t' * indent

        class_idx = self.u32()  # Child objects have explicit class_idx
        class_name = self.get_str(class_idx)
        prop_count = self.u32()
        child_count = self.u32()

        lines.append(f'{ind}[{class_name}]')
        lines.append(f'{ind}{{')

        # Add _RefID as first property
        lines.append(f'{ind}\t_RefID = {self.next_refid()}')

        # Parse properties
        for _ in range(prop_count):
            prop_line = self.parse_property()
            if prop_line is not None:  # Skip None (filtered properties like _RefID)
                lines.append(f'{ind}\t{prop_line}')

        # Add blank line after properties, before child sections
        if prop_count > 0 or child_count > 0:
            lines.append('')

        # Parse child sections
        for _ in range(child_count):
            section_lines = self.parse_section(indent + 1)
            lines.extend(section_lines)

        lines.append(f'{ind}}}')
        return lines

    def parse_section(self, indent=0):
        """Parse a section and return as text lines.

        There are two section formats:
        1. Container section (section_type = 0): Contains child objects with their own class_idx
           Format: name_idx + 0 + obj_count + objects
        2. Inline object section (section_type != 0): Properties embedded, class in section name
           Format: name_idx + prop_count + child_count + properties + child_sections
        """
        lines = []
        ind = '\t' * indent

        name_idx = self.u32()
        section_name = self.get_str(name_idx)
        second_field = self.u32()

        if second_field == 0:
            # Container section with child objects
            obj_count = self.u32()
            lines.append(f'{ind}[{section_name}]')
            lines.append(f'{ind}{{')

            # Add blank line at start of section
            lines.append('')

            for _ in range(obj_count):
                obj_lines = self.parse_child_object(indent + 1)
                lines.extend(obj_lines)

            lines.append(f'{ind}}}')
        else:
            # Inline object section - the section name includes class info
            # Format: section_name + prop_count + child_count + props + sections
            # Example: "ToolTip : cPrismToolTip" becomes [ToolTip : cPrismToolTip]
            prop_count = second_field
            child_count = self.u32()

            lines.append(f'{ind}[{section_name}]')
            lines.append(f'{ind}{{')

            # Add blank line at start of section
            lines.append('')

            # Parse properties
            for _ in range(prop_count):
                prop_line = self.parse_property()
                if prop_line is not None:  # Skip None (filtered properties like _RefID)
                    lines.append(f'{ind}\t{prop_line}')

            # Add blank line after properties if there are child sections
            if prop_count > 0 and child_count > 0:
                lines.append('')

            # Parse child sections
            for _ in range(child_count):
                section_lines = self.parse_section(indent + 1)
                lines.extend(section_lines)

            lines.append(f'{ind}}}')

        return lines

    def parse(self):
        """Parse the entire file and return text representation."""
        # Skip header (string table offset + reserved bytes)
        self.pos = 16

        try:
            lines = self.parse_root_object(0)
            # Add leading blank line and trailing newline to match original format
            return '\r\n' + '\r\n'.join(lines) + '\r\n'
        except Exception as e:
            raise ValueError(f'Parse error at 0x{self.pos:X}: {e}')


class SimpleInfParser:
    """Parser for 'simple' binary INF files (without _RefID, like defaultmusics.inf).

    Simple format structure:
    - Header: sto(4) + reserved(4) + section_count(4) + reserved(4)
    - Section 0: prop_count(4) + child_count(4) + properties (name from strings[0])
    - Sections 1+: name_idx(4) + prop_count(4) + child_count(4) + properties
    - Property: name_idx(4) + val_count(1) + type(1) + values
    - Value: string_idx(4) for type 0, double(8) for type 1
    """

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.strings = []
        self._load_strings()

    def _load_strings(self):
        """Load string table."""
        sto = struct.unpack('<I', self.data[0:4])[0]
        pos = sto
        str_count = struct.unpack('<I', self.data[pos:pos+4])[0]
        pos += 4
        for _ in range(str_count):
            end = self.data.find(b'\x00', pos)
            if end == -1:
                break
            self.strings.append(self.data[pos:end].decode('utf-8', errors='replace'))
            pos = end + 1

    def u32(self):
        val = struct.unpack('<I', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return val

    def u8(self):
        val = self.data[self.pos]
        self.pos += 1
        return val

    def get_str(self, idx):
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return f"<invalid:{idx}>"

    def parse_properties(self, count):
        """Parse properties and return list of (name, values) tuples."""
        props = []
        for _ in range(count):
            name_idx = self.u32()
            val_count = self.u8()
            vtype = self.u8()

            values = []
            for v in range(val_count):
                # After the first value, there's a type marker before each value
                if v > 0:
                    vtype = self.u8()

                if vtype == 0:  # string
                    vidx = self.u32()
                    values.append(self.get_str(vidx))
                elif vtype == 1:  # double
                    val = struct.unpack('<d', self.data[self.pos:self.pos+8])[0]
                    self.pos += 8
                    values.append(val)

            props.append((self.get_str(name_idx), values))
        return props

    def format_value(self, val):
        """Format a single value."""
        if isinstance(val, str):
            # In simple format, only quote strings that contain spaces or special chars
            if ' ' in val or '/' in val or '\\' in val or ',' in val:
                return f'"{val}"'
            return val
        else:
            # Format numbers without trailing zeros
            if val == int(val):
                return str(int(val))
            else:
                return str(val)

    def format_section(self, name, props):
        """Format a section as text."""
        lines = [f'[{name}]', '{']
        for pname, values in props:
            if len(values) == 1:
                # Single value - simple format (no quotes around simple strings)
                val = values[0]
                lines.append(f'\t{pname}={self.format_value(val)}')
            else:
                # Multiple values - comma-separated (no spaces after commas)
                formatted = ','.join(self.format_value(v) for v in values)
                lines.append(f'\t{pname}={formatted}')
        lines.append('}')
        return lines

    def parse(self):
        """Parse the entire file and return text representation."""
        # Header
        self.pos = 8
        section_count = self.u32()
        self.pos = 16  # Skip to data section

        all_lines = []

        # Section 0: name is strings[0], no name_idx field
        prop_count = self.u32()
        child_count = self.u32()  # Usually 0 for simple format
        props = self.parse_properties(prop_count)
        all_lines.extend(self.format_section(self.get_str(0), props))

        # Remaining sections: have name_idx field
        for _ in range(1, section_count):
            name_idx = self.u32()
            prop_count = self.u32()
            child_count = self.u32()  # Usually 0
            props = self.parse_properties(prop_count)
            all_lines.append('')  # Blank line between sections
            all_lines.extend(self.format_section(self.get_str(name_idx), props))

        return '\r\n'.join(all_lines) + '\r\n'


def is_simple_format(data):
    """Check if data is 'simple' binary format (vs 'object' format with _RefID).

    Simple format: multiple top-level sections, no nested objects
    - [0x08] = section_count (> 1)
    - [0x14] = 0 (no child objects)

    Object format: single root object with nested children
    - [0x08] = 1 (single root)
    - [0x14] = child_count (usually > 0)
    - First string often contains ' : ' (class name)
    """
    if len(data) < 24:
        return False
    sto = struct.unpack('<I', data[0:4])[0]
    if sto < 16 or sto >= len(data):
        return False

    # Check structural indicators
    val_08 = struct.unpack('<I', data[8:12])[0]   # section_count or 1
    val_14 = struct.unpack('<I', data[20:24])[0]  # child_count at offset 0x14

    # Simple format has section_count > 1 at offset 8, and child_count = 0 at offset 0x14
    # Object format has 1 at offset 8 and often child_count > 0
    if val_08 > 1 and val_14 == 0:
        return True

    # Additional check: object format first string often contains ' : '
    str_count = struct.unpack('<I', data[sto:sto+4])[0]
    if str_count == 0:
        return False
    pos = sto + 4
    end = data.find(b'\x00', pos)
    if end == -1:
        return False
    first_str = data[pos:end].decode('utf-8', errors='replace')

    # If first string contains ' : ', it's object format
    if ' : ' in first_str:
        return False

    # Default to simple if section_count > 1
    return val_08 > 1


def binary_to_text(data):
    """Convert decompressed binary INF to text format."""
    if is_simple_format(data):
        parser = SimpleInfParser(data)
    else:
        parser = BinaryInfParser(data)
    return parser.parse()

def is_text_inf(data):
    """Check if data is a text INF file (not binary)."""
    # Binary INF starts with string table offset (small number) followed by nulls
    # Text INF is human-readable with sections like [ClassName] and properties
    if len(data) < 20:
        return False

    # Check if it looks like binary INF structure
    # Binary: first 4 bytes are string table offset (usually > 0x10 and < file size)
    sto = struct.unpack('<I', data[0:4])[0]
    if 16 <= sto < len(data) and data[4:8] == b'\x00\x00\x00\x00':
        return False  # Likely binary INF

    # Check for compressed magic
    if data[0:4] in MAGICS:
        return False

    # Try to decode as text and look for INI-like structure
    try:
        text = data[:500].decode('utf-8', errors='strict')
        # Text INF should have section markers and be mostly printable
        if '[' in text and ']' in text and '{' in text:
            return True
        # Or start with comment/section
        stripped = text.strip()
        if stripped.startswith('[') or stripped.startswith(';') or stripped.startswith('#'):
            return True
    except:
        pass

    return False

def analyze_binary_inf(data):
    """Analyze decompressed binary INF structure."""
    if len(data) < 16:
        return None

    info = {}
    info['size'] = len(data)
    info['string_table_offset'] = struct.unpack('<I', data[0:4])[0]

    # Analyze string table
    sto = info['string_table_offset']
    if 16 <= sto < len(data) - 4:
        info['string_count'] = struct.unpack('<I', data[sto:sto+4])[0]

        # Read first few strings
        strings = []
        pos = sto + 4
        for i in range(min(info['string_count'], 20)):
            if pos >= len(data):
                break
            end = data.find(b'\x00', pos)
            if end == -1:
                break
            try:
                s = data[pos:end].decode('utf-8', errors='replace')
                strings.append(s)
            except:
                strings.append(f'<binary@{pos}>')
            pos = end + 1
        info['sample_strings'] = strings

    return info

def decompress_inf(input_path, output_path, verbose=False, to_text=False):
    """Decompress a .inf file using the custom format.

    Args:
        input_path: Path to input .inf file
        output_path: Path to write output (or None to skip writing)
        verbose: Show detailed output
        to_text: Convert binary INF to text format
    """
    with open(input_path, 'rb') as f:
        data = f.read()

    if len(data) < 12:
        if verbose:
            print(f"  Skipping {input_path} - too small")
        return None

    # Check for text INF
    if is_text_inf(data):
        if verbose:
            print(f"  Skipping {input_path} - text format")
        # Copy text file to output
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(data)
        return 'text'

    # Check magic signature
    magic = data[0:4]
    version = get_version(magic)
    decompressed = None

    if version is None:
        # Check if already decompressed binary
        sto = struct.unpack('<I', data[0:4])[0]
        if 16 <= sto < len(data):
            if verbose:
                print(f"  Processing {input_path} - already decompressed binary")
            decompressed = data
        else:
            if verbose:
                print(f"  Skipping {input_path} - unknown format (magic: {magic.hex()})")
            return None
    else:
        # Read header
        compressed_size = struct.unpack('<I', data[4:8])[0]
        uncompressed_size = struct.unpack('<I', data[8:12])[0]

        if verbose:
            print(f"  Version: {version}, Compressed: {compressed_size}, Uncompressed: {uncompressed_size}")

        # Decompress (skip 12-byte header)
        compressed_data = data[12:]

        try:
            # Try standard zlib
            decompressed = zlib.decompress(compressed_data)
        except zlib.error:
            try:
                # Try raw deflate
                decompressed = zlib.decompress(compressed_data, -15)
            except zlib.error:
                try:
                    # Try with explicit size
                    decompressed = zlib.decompress(compressed_data[:compressed_size])
                except Exception as e:
                    print(f"  Error decompressing {input_path}: {e}")
                    return False

    # Convert to text if requested
    if to_text and decompressed:
        try:
            text_content = binary_to_text(decompressed)
            if output_path:
                # Use binary mode to preserve exact CRLF line endings
                with open(output_path, 'wb') as f:
                    f.write(text_content.encode('utf-8'))
            print(f"  Converted: {os.path.basename(input_path)} -> text ({len(text_content)} chars)")
            return 'converted'
        except Exception as e:
            print(f"  Error converting {input_path} to text: {e}")
            # Fall back to writing binary
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(decompressed)
            return 'binary'

    # Write decompressed binary data
    if output_path:
        with open(output_path, 'wb') as f:
            f.write(decompressed)

    if verbose:
        info = analyze_binary_inf(decompressed)
        if info:
            print(f"  String table at 0x{info['string_table_offset']:X}, {info.get('string_count', '?')} strings")
            if 'sample_strings' in info and info['sample_strings']:
                print(f"  Sample: {info['sample_strings'][:5]}")

    print(f"  Decompressed: {os.path.basename(input_path)} ({len(data)} -> {len(decompressed)} bytes)")
    return True

def process_directory(input_dir, output_dir, verbose=False, in_place=False, to_text=False):
    """Process all INF and BASE files in a directory."""
    if in_place:
        output_dir = input_dir

    os.makedirs(output_dir, exist_ok=True)

    # Find both .inf and .base files
    inf_files = glob.glob(os.path.join(input_dir, "**/*.inf"), recursive=True)
    base_files = glob.glob(os.path.join(input_dir, "**/*.base"), recursive=True)
    all_files = inf_files + base_files
    print(f"Found {len(inf_files)} .inf files and {len(base_files)} .base files")
    print(f"Output: {output_dir}")
    if to_text:
        print(f"Mode: Convert to text")
    print()

    stats = {'decompressed': 0, 'converted': 0, 'text': 0, 'binary': 0, 'error': 0, 'skipped': 0}

    for inf_file in all_files:
        rel_path = os.path.relpath(inf_file, input_dir)
        output_path = os.path.join(output_dir, rel_path)
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        result = decompress_inf(inf_file, output_path, verbose=verbose, to_text=to_text)
        if result is True:
            stats['decompressed'] += 1
        elif result == 'converted':
            stats['converted'] += 1
        elif result == 'text':
            stats['text'] += 1
        elif result == 'binary':
            stats['binary'] += 1
        elif result is False:
            stats['error'] += 1
        else:
            stats['skipped'] += 1

    print(f"\nDone!")
    if to_text:
        print(f"  Converted to text: {stats['converted']}")
    else:
        print(f"  Decompressed: {stats['decompressed']}")
    print(f"  Already text: {stats['text']}")
    print(f"  Binary (fallback): {stats['binary']}")
    print(f"  Errors: {stats['error']}")
    print(f"  Skipped: {stats['skipped']}")


def main():
    parser = argparse.ArgumentParser(
        description='Decompress WarFront: Turning Point .inf files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python decompress_inf.py                          # Process Inf/ -> Inf_decompressed/
  python decompress_inf.py -t                       # Convert to text format
  python decompress_inf.py -i Inf                   # Decompress in place
  python decompress_inf.py -d Data/Inf Output/Inf   # Custom folders
  python decompress_inf.py -t -d Inf Inf_text       # Convert to text, custom folders
  python decompress_inf.py -f file.inf out.inf      # Single file
  python decompress_inf.py -t -f file.inf out.inf   # Single file to text
  python decompress_inf.py -a file.inf              # Analyze without writing
'''
    )
    parser.add_argument('-d', '--dir', nargs=2, metavar=('INPUT', 'OUTPUT'),
                       help='Process directory INPUT to OUTPUT')
    parser.add_argument('-i', '--in-place', metavar='DIR',
                       help='Decompress files in place in DIR')
    parser.add_argument('-f', '--file', nargs=2, metavar=('INPUT', 'OUTPUT'),
                       help='Process single file')
    parser.add_argument('-a', '--analyze', metavar='FILE',
                       help='Analyze file without writing')
    parser.add_argument('-t', '--to-text', action='store_true',
                       help='Convert binary INF to human-readable text format')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed output')

    args = parser.parse_args()

    if args.analyze:
        # Just analyze a file
        with open(args.analyze, 'rb') as f:
            data = f.read()

        magic = data[0:4]
        version = get_version(magic)

        if version is not None:
            print(f"Compressed INF, version {version}")
            print(f"Magic: {magic.hex()}")
            compressed_size = struct.unpack('<I', data[4:8])[0]
            uncompressed_size = struct.unpack('<I', data[8:12])[0]
            print(f"Compressed size: {compressed_size}")
            print(f"Uncompressed size: {uncompressed_size}")

            try:
                decompressed = zlib.decompress(data[12:])
                print(f"\nDecompressed successfully ({len(decompressed)} bytes)")
                info = analyze_binary_inf(decompressed)
                if info:
                    print(f"String table offset: 0x{info['string_table_offset']:X}")
                    print(f"String count: {info.get('string_count', 'unknown')}")
                    if 'sample_strings' in info:
                        print(f"\nStrings:")
                        for i, s in enumerate(info['sample_strings']):
                            print(f"  [{i}] {s}")
            except Exception as e:
                print(f"Decompression failed: {e}")
        elif is_text_inf(data):
            print("Text INF file")
            print(data[:500].decode('utf-8', errors='replace'))
        else:
            print("Unknown format or already decompressed binary")
            info = analyze_binary_inf(data)
            if info:
                print(f"String table offset: 0x{info['string_table_offset']:X}")
                print(f"String count: {info.get('string_count', 'unknown')}")

    elif args.file:
        decompress_inf(args.file[0], args.file[1], verbose=True, to_text=args.to_text)

    elif args.in_place:
        process_directory(args.in_place, args.in_place, verbose=args.verbose, in_place=True, to_text=args.to_text)

    elif args.dir:
        process_directory(args.dir[0], args.dir[1], verbose=args.verbose, to_text=args.to_text)

    else:
        # Default: process Inf folder
        input_dir = "Inf"
        output_dir = "Inf_text" if args.to_text else "Inf_decompressed"

        if not os.path.exists(input_dir):
            print(f"Error: '{input_dir}' folder not found")
            print("Use -d to specify input/output directories")
            return

        process_directory(input_dir, output_dir, verbose=args.verbose, to_text=args.to_text)


if __name__ == "__main__":
    main()
