"""
WarFront: Turning Point INF File Tool

Converts the game's binary INF files to editable text and compiles text back
to binary. Binary -> text -> binary reproduces the original files byte for byte.

COMPRESSED FILE (12-byte header + zlib stream):
- 0x00  magic: AA A5 FF FF = version 3, AB A5 FF FF = version 2
        (AC/AD A5 FF FF = versions 1/0 are recognised by the game but unseen)
- 0x04  u32 always 1
- 0x08  u32 uncompressed size
- 0x0C  zlib data (default compression level)

DECOMPRESSED BINARY:
- 0x00  u32 string table offset
- 0x04  u32 root property count
- 0x08  u32 root child node count
- 0x0C  root properties, then root child nodes

  Node:      name_idx, u32 prop_count, u32 child_count, properties, child nodes
  Property:  name_idx, u8 value_count, value_count x (u8 type, data)
  Value:     type 0 = string (str_idx), 1 = double (f64), 2 = wide string (wstr_idx)

  String indices (name_idx/str_idx/wstr_idx) are u32 in version 3, u16 in version 2.

- String table:      u32 count, NUL-terminated strings, numbered in order of
                     first use during a depth-first walk of the tree
- Wide string table: u32 count, (u32 char_count + UTF-16LE data) per string

The text format is the one the game reads when binaryinffiles = 0:

  RootProperty = "value"

  [PRGAME : cPRGame]          <- node named "PRGAME : cPRGame"
  {
      _RefID = 1
      Size = 1024, 768        <- multiple values
      Title = L"wide"         <- wide string

      [Controls *]            <- container: children are "[: cClass]" nodes
      {

          [: cPrismButton]
          {
              ...
          }
      }
  }
"""

import argparse
import glob
import math
import os
import re
import struct
import zlib

MAGIC_BY_VERSION = {
    3: b'\xAA\xA5\xFF\xFF',
    2: b'\xAB\xA5\xFF\xFF',
    1: b'\xAC\xA5\xFF\xFF',
    0: b'\xAD\xA5\xFF\xFF',
}
VERSION_BY_MAGIC = {magic: version for version, magic in MAGIC_BY_VERSION.items()}

# Width in bytes of string table indices, per format version
INDEX_SIZE_BY_VERSION = {3: 4, 2: 2}

TYPE_STRING = 0
TYPE_DOUBLE = 1
TYPE_WSTRING = 2

TEXT_ENCODING = 'latin-1'  # lossless for any byte; all known game strings are ASCII


def get_version(magic_bytes):
    """Get version number from magic bytes, or None if not a compressed INF."""
    return VERSION_BY_MAGIC.get(bytes(magic_bytes[:4]))


class WString(str):
    """A wide (UTF-16) string value, written as L"..." in text."""


class Node:
    """A named node holding properties and child nodes.

    The document root is a Node with name None. Properties are kept as an
    ordered list of (name, values) pairs because names may repeat.
    """

    __slots__ = ('name', 'props', 'children')

    def __init__(self, name=None, props=None, children=None):
        self.name = name
        self.props = props if props is not None else []
        self.children = children if children is not None else []

    def __eq__(self, other):
        return (isinstance(other, Node) and self.name == other.name
                and self.props == other.props and self.children == other.children)

    def __repr__(self):
        return f'Node({self.name!r}, {len(self.props)} props, {len(self.children)} children)'


# ---------------------------------------------------------------------------
# Binary reading
# ---------------------------------------------------------------------------

class BinaryFormatError(ValueError):
    pass


class _BinaryReader:
    def __init__(self, data, index_size):
        self.data = data
        self.index_size = index_size
        self.pos = 0
        if len(data) < 12:
            raise BinaryFormatError('file too small')
        self.string_table_offset = struct.unpack_from('<I', data, 0)[0]
        if not 12 <= self.string_table_offset <= len(data) - 8:
            raise BinaryFormatError(f'invalid string table offset 0x{self.string_table_offset:X}')
        self._load_string_tables()

    def _need(self, n):
        if self.pos + n > len(self.data):
            raise BinaryFormatError(f'unexpected end of data at 0x{self.pos:X}')

    def u8(self):
        self._need(1)
        self.pos += 1
        return self.data[self.pos - 1]

    def u32(self):
        self._need(4)
        self.pos += 4
        return struct.unpack_from('<I', self.data, self.pos - 4)[0]

    def f64(self):
        self._need(8)
        self.pos += 8
        return struct.unpack_from('<d', self.data, self.pos - 8)[0]

    def index(self):
        self._need(self.index_size)
        self.pos += self.index_size
        return int.from_bytes(self.data[self.pos - self.index_size:self.pos], 'little')

    def _load_string_tables(self):
        self.pos = self.string_table_offset
        self.strings = []
        for _ in range(self.u32()):
            end = self.data.find(b'\x00', self.pos)
            if end == -1:
                raise BinaryFormatError('unterminated string in string table')
            self.strings.append(self.data[self.pos:end].decode(TEXT_ENCODING))
            self.pos = end + 1

        self.wstrings = []
        for _ in range(self.u32()):
            byte_len = self.u32() * 2
            self._need(byte_len)
            self.wstrings.append(WString(self.data[self.pos:self.pos + byte_len].decode('utf-16le')))
            self.pos += byte_len

        if self.pos != len(self.data):
            raise BinaryFormatError(f'{len(self.data) - self.pos} unexpected bytes after string tables')

    def string(self):
        idx = self.index()
        if idx >= len(self.strings):
            raise BinaryFormatError(f'string index {idx} out of range at 0x{self.pos:X}')
        return self.strings[idx]

    def wstring(self):
        idx = self.index()
        if idx >= len(self.wstrings):
            raise BinaryFormatError(f'wide string index {idx} out of range at 0x{self.pos:X}')
        return self.wstrings[idx]

    def read_props(self, count, props):
        for _ in range(count):
            name = self.string()
            values = []
            for _ in range(self.u8()):
                value_type = self.u8()
                if value_type == TYPE_STRING:
                    values.append(self.string())
                elif value_type == TYPE_DOUBLE:
                    values.append(self.f64())
                elif value_type == TYPE_WSTRING:
                    values.append(self.wstring())
                else:
                    raise BinaryFormatError(f'unknown value type {value_type} at 0x{self.pos - 1:X}')
            props.append((name, values))

    def read_children(self, count, children):
        for _ in range(count):
            node = Node(self.string())
            prop_count = self.u32()
            child_count = self.u32()
            self.read_props(prop_count, node.props)
            self.read_children(child_count, node.children)
            children.append(node)

    def read(self):
        self.pos = 4
        root = Node()
        prop_count = self.u32()
        child_count = self.u32()
        self.read_props(prop_count, root.props)
        self.read_children(child_count, root.children)
        if self.pos != self.string_table_offset:
            raise BinaryFormatError(
                f'tree ends at 0x{self.pos:X}, string table starts at 0x{self.string_table_offset:X}')
        return root


def read_binary(data, version=None):
    """Parse decompressed binary INF data into a Node tree.

    Returns (root, version). Decompressed data carries no version marker, so
    when version is None each known index width is tried in turn.
    """
    versions = [version] if version is not None else [3, 2]
    error = None
    for v in versions:
        if v not in INDEX_SIZE_BY_VERSION:
            raise BinaryFormatError(f'unsupported format version {v}')
        try:
            return _BinaryReader(data, INDEX_SIZE_BY_VERSION[v]).read(), v
        except (BinaryFormatError, RecursionError) as e:
            error = error or e
    raise error


def decompress(data):
    """Decompress a compressed INF. Returns (decompressed_data, version)."""
    version = get_version(data)
    if version is None:
        raise BinaryFormatError('not a compressed INF (bad magic)')
    raw = zlib.decompress(data[12:])
    expected = struct.unpack_from('<I', data, 8)[0]
    if len(raw) != expected:
        raise BinaryFormatError(f'decompressed {len(raw)} bytes, header says {expected}')
    return raw, version


def compress(raw, version=3):
    """Wrap decompressed binary INF data in the compressed file format."""
    return MAGIC_BY_VERSION[version] + struct.pack('<II', 1, len(raw)) + zlib.compress(raw)


# ---------------------------------------------------------------------------
# Binary writing
# ---------------------------------------------------------------------------

def write_binary(root, version=3):
    """Serialize a Node tree to decompressed binary INF data."""
    index_size = INDEX_SIZE_BY_VERSION[version]
    max_index = (1 << (8 * index_size)) - 1
    strings = {}
    wstrings = {}
    out = bytearray(b'\x00' * 4)

    def intern(table, s):
        idx = table.setdefault(s, len(table))
        if idx > max_index:
            raise ValueError(f'too many strings for version {version} format')
        out.extend(idx.to_bytes(index_size, 'little'))

    def write_props(props):
        for name, values in props:
            if len(values) > 255:
                raise ValueError(f'property {name!r} has {len(values)} values (max 255)')
            intern(strings, name)
            out.append(len(values))
            for value in values:
                if isinstance(value, WString):
                    out.append(TYPE_WSTRING)
                    intern(wstrings, str(value))
                elif isinstance(value, str):
                    out.append(TYPE_STRING)
                    intern(strings, value)
                else:
                    out.append(TYPE_DOUBLE)
                    out.extend(struct.pack('<d', value))

    def write_children(children):
        for node in children:
            intern(strings, node.name)
            out.extend(struct.pack('<II', len(node.props), len(node.children)))
            write_props(node.props)
            write_children(node.children)

    out.extend(struct.pack('<II', len(root.props), len(root.children)))
    write_props(root.props)
    write_children(root.children)

    struct.pack_into('<I', out, 0, len(out))
    out.extend(struct.pack('<I', len(strings)))
    for s in strings:
        out.extend(s.encode(TEXT_ENCODING) + b'\x00')
    out.extend(struct.pack('<I', len(wstrings)))
    for s in wstrings:
        encoded = s.encode('utf-16le')
        out.extend(struct.pack('<I', len(encoded) // 2) + encoded)
    return bytes(out)


# ---------------------------------------------------------------------------
# Text writing
# ---------------------------------------------------------------------------

def format_double(v):
    is_negative_zero = v == 0 and math.copysign(1.0, v) < 0
    if v.is_integer() and abs(v) < 1e15 and not is_negative_zero:
        return str(int(v))
    return repr(v)


def format_value(value):
    if isinstance(value, WString):
        return f'L"{value}"'
    if isinstance(value, str):
        return f'"{value}"'
    return format_double(value)


def _check_text_safe(s, what):
    if '"' in s or '\r' in s or '\n' in s:
        raise ValueError(f'{what} {s!r} cannot be represented in text format')


def to_text(root):
    """Render a Node tree in the game's text INF format (CRLF line endings)."""
    lines = []

    def emit_props(props, ind):
        for name, values in props:
            for v in values:
                if isinstance(v, str):
                    _check_text_safe(v, 'string')
            lines.append(f'{ind}{name} = {", ".join(format_value(v) for v in values)}')

    def emit_node(node, depth):
        ind = '\t' * depth
        _check_text_safe(node.name, 'section name')
        lines.append(f'{ind}[{node.name}]')
        lines.append(f'{ind}{{')
        if node.name.endswith('*') and not node.props:
            lines.append('')  # container sections open with a blank line
        emit_props(node.props, ind + '\t')
        if node.props and node.children:
            lines.append('')
        for child in node.children:
            emit_node(child, depth + 1)
        lines.append(f'{ind}}}')

    emit_props(root.props, '')
    if root.props and root.children:
        lines.append('')
    for i, node in enumerate(root.children):
        if i:
            lines.append('')
        emit_node(node, 0)
    return '\r\n'.join(lines) + '\r\n'


# ---------------------------------------------------------------------------
# Text parsing
# ---------------------------------------------------------------------------

class TextFormatError(ValueError):
    pass


_NUMBER_RE = re.compile(r'[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$')

_DEFINE_RE = re.compile(r'#define\s+(\w+)(?:\s+(.*))?$')


def _define_pattern(defines):
    """Regex matching a quoted string (group 0, left alone) or a defined name (group 1)."""
    names = '|'.join(sorted(map(re.escape, defines), key=len, reverse=True))
    return re.compile(r'L?"[^"]*"|\b(' + names + r')\b')


def _parse_values(text, lineno):
    values = []
    pos = 0
    n = len(text)
    while True:
        while pos < n and text[pos] in ' \t':
            pos += 1
        if text.startswith('"', pos) or text.startswith('L"', pos):
            wide = text[pos] == 'L'
            start = pos + (2 if wide else 1)
            end = text.find('"', start)
            if end == -1:
                raise TextFormatError(f'line {lineno}: unterminated string')
            s = text[start:end]
            values.append(WString(s) if wide else s)
            pos = end + 1
            while pos < n and text[pos] in ' \t':
                pos += 1
        else:
            end = text.find(',', pos)
            end = n if end == -1 else end
            token = text[pos:end].strip()
            pos = end
            if _NUMBER_RE.match(token):
                values.append(float(token))
            elif token:
                values.append(token)
            elif pos < n or values:
                raise TextFormatError(f'line {lineno}: empty value')
        if pos >= n:
            return values
        if text[pos] != ',':
            raise TextFormatError(f'line {lineno}: expected "," after value, got {text[pos:]!r}')
        pos += 1


def parse_text(text):
    """Parse a text INF (as written by the game's developers or to_text) into a Node tree.

    Handles the simple object-like `#define NAME value` macros used by a few
    developer-written files (e.g. the sales preview's GlobalIncludes.inf and
    StateIcons.inf): after a `#define` line, NAME is replaced by its value
    wherever it appears as a whole word outside quoted strings.
    """
    root = Node()
    stack = [root]
    pending = None  # section header waiting for its "{"
    defines = {}
    pattern = None

    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(';'):
            continue
        if line.startswith('#'):
            m = _DEFINE_RE.match(line)
            if not m:
                raise TextFormatError(f'line {lineno}: unsupported preprocessor directive: {line!r}')
            defines[m.group(1)] = (m.group(2) or '').strip()
            pattern = _define_pattern(defines)
            continue
        if pattern is not None:
            line = pattern.sub(lambda m: defines[m.group(1)] if m.group(1) is not None else m.group(0), line)
        if pending is not None:
            if line != '{':
                raise TextFormatError(f'line {lineno}: expected "{{" after [{pending.name}]')
            stack[-1].children.append(pending)
            stack.append(pending)
            pending = None
        elif line.startswith('['):
            if not line.endswith(']'):
                raise TextFormatError(f'line {lineno}: malformed section header {line!r}')
            pending = Node(line[1:-1].strip())
        elif line == '}':
            if len(stack) == 1:
                raise TextFormatError(f'line {lineno}: unmatched "}}"')
            stack.pop()
        elif '=' in line:
            name, _, value_text = line.partition('=')
            name = name.strip()
            if not name:
                raise TextFormatError(f'line {lineno}: property without a name')
            stack[-1].props.append((name, _parse_values(value_text, lineno)))
        else:
            raise TextFormatError(f'line {lineno}: unexpected {line!r}')

    if pending is not None:
        raise TextFormatError(f'section [{pending.name}] has no body')
    if len(stack) != 1:
        raise TextFormatError(f'unclosed section [{stack[-1].name}]')
    return root


# ---------------------------------------------------------------------------
# High-level conversions
# ---------------------------------------------------------------------------

def add_refids(root):
    """Number object nodes with sequential _RefID values, if the file has none.

    Most shipped binaries have had their _RefIDs stripped by the developers'
    compiler. The game loads text files without them; this numbers top-level
    "Name : cClass" objects and "[: cClass]" objects inside container sections,
    the scheme earlier versions of this tool intended. Returns root.
    """
    def has_refids(node):
        return any(name == '_RefID' for name, _ in node.props) or any(map(has_refids, node.children))

    if has_refids(root):
        return root
    counter = [0]

    def walk(node, numbered):
        if numbered:
            counter[0] += 1
            node.props.insert(0, ('_RefID', [float(counter[0])]))
        for child in node.children:
            walk(child, child.name.startswith(':'))

    for node in root.children:
        walk(node, ':' in node.name)
    return root


def binary_to_text(data, refids=False):
    """Convert binary INF data (compressed or decompressed) to text."""
    if get_version(data) is not None:
        raw, version = decompress(data)
    else:
        raw, version = data, None
    root = read_binary(raw, version)[0]
    return to_text(add_refids(root) if refids else root)


def text_to_binary(text, version=3, compressed=True):
    """Compile text INF to binary INF data."""
    raw = write_binary(parse_text(text), version)
    return compress(raw, version) if compressed else raw


def detect_format(data):
    """Classify file content as 'compressed', 'binary', 'text' or None."""
    if get_version(data) is not None:
        return 'compressed'
    try:
        read_binary(data)
        return 'binary'
    except (BinaryFormatError, struct.error):
        pass
    try:
        parse_text(data.decode(TEXT_ENCODING))
        return 'text'
    except TextFormatError:
        return None


def is_text_inf(data):
    return detect_format(data) == 'text'


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------

MODES = ('text', 'decompress', 'binary')


def convert_file(input_path, output_path, mode, version=3, verbose=False, refids=False):
    """Convert one file. mode is 'text', 'decompress' or 'binary'.

    Returns 'converted', 'copied' (already in the target format), or 'error'.
    """
    with open(input_path, 'rb') as f:
        data = f.read()
    name = os.path.basename(input_path)
    kind = detect_format(data)

    def write(content):
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(content)

    try:
        if kind is None:
            print(f'  Skipping {name}: unrecognised format')
            return 'error'

        if mode == 'binary':
            if kind != 'text':
                write(data)
                return 'copied'
            write(text_to_binary(data.decode(TEXT_ENCODING), version))
        else:
            if kind == 'text':
                write(data)
                return 'copied'
            if kind == 'compressed':
                raw, file_version = decompress(data)
            else:
                raw, file_version = data, None
            if mode == 'decompress':
                write(raw)
            else:
                root = read_binary(raw, file_version)[0]
                if refids:
                    add_refids(root)
                write(to_text(root).encode(TEXT_ENCODING))
    except (ValueError, zlib.error) as e:
        print(f'  Error converting {name}: {e}')
        return 'error'

    if verbose:
        print(f'  Converted: {name}')
    return 'converted'


def process_directory(input_dir, output_dir, mode, version=3, verbose=False, refids=False):
    """Convert all .inf and .base files under input_dir into output_dir."""
    files = sorted(
        path for pattern in ('**/*.inf', '**/*.base')
        for path in glob.glob(os.path.join(input_dir, pattern), recursive=True))
    print(f'Found {len(files)} files in {input_dir}')
    print(f'Output: {output_dir} ({mode})')

    stats = {'converted': 0, 'copied': 0, 'error': 0}
    for path in files:
        output_path = os.path.join(output_dir, os.path.relpath(path, input_dir))
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        stats[convert_file(path, output_path, mode, version, verbose, refids)] += 1

    print(f'\nDone! Converted: {stats["converted"]}, '
          f'already in target format: {stats["copied"]}, errors: {stats["error"]}')
    return stats


def analyze_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    kind = detect_format(data)
    print(f'File: {path} ({len(data)} bytes)')
    print(f'Format: {kind or "unknown"}')
    if kind is None:
        return
    if kind == 'text':
        root = parse_text(data.decode(TEXT_ENCODING))
        version = None
    else:
        raw, version = decompress(data) if kind == 'compressed' else (data, None)
        root, version = read_binary(raw, version)
        print(f'Version: {version} ({INDEX_SIZE_BY_VERSION[version] * 8}-bit string indices)')
        print(f'Decompressed size: {len(raw)} bytes')

    counts = {'nodes': 0, 'props': len(root.props)}

    def walk(node):
        for child in node.children:
            counts['nodes'] += 1
            counts['props'] += len(child.props)
            walk(child)
    walk(root)
    print(f'Root properties: {len(root.props)}, top-level sections: {len(root.children)}')
    print(f'Total sections: {counts["nodes"]}, total properties: {counts["props"]}')
    for node in root.children[:10]:
        print(f'  [{node.name}]')


def main(argv=None, prog=None):
    parser = argparse.ArgumentParser(
        prog=prog,
        description='Convert WarFront: Turning Point INF files between binary and text',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -t                         # Inf/ -> Inf_text/ (binary to text)
  %(prog)s -t -d Data/Inf Out/Inf     # Custom folders
  %(prog)s -t -f game.inf game.txt    # Single file to text
  %(prog)s -b -f game.txt game.inf    # Compile text back to binary
  %(prog)s -b -d Inf_text Inf_binary  # Compile a whole folder
  %(prog)s -d Inf Inf_decompressed    # Decompress only
  %(prog)s -a file.inf                # Show file structure
''')
    parser.add_argument('-d', '--dir', nargs=2, metavar=('INPUT', 'OUTPUT'),
                        help='process directory INPUT into OUTPUT')
    parser.add_argument('-i', '--in-place', metavar='DIR',
                        help='convert files in DIR in place (overwrites originals)')
    parser.add_argument('-f', '--file', nargs=2, metavar=('INPUT', 'OUTPUT'),
                        help='process a single file')
    parser.add_argument('-a', '--analyze', metavar='FILE',
                        help='show file structure without writing')
    direction = parser.add_mutually_exclusive_group()
    direction.add_argument('-t', '--to-text', action='store_true',
                           help='convert binary INF to text')
    direction.add_argument('-b', '--to-binary', action='store_true',
                           help='compile text INF to compressed binary')
    parser.add_argument('--format-version', type=int, choices=sorted(INDEX_SIZE_BY_VERSION), default=3,
                        help='binary version to write with -b (default: 3)')
    parser.add_argument('--add-refids', action='store_true',
                        help='with -t, add sequential _RefIDs to files that have none')
    parser.add_argument('-v', '--verbose', action='store_true', help='show detailed output')
    args = parser.parse_args(argv)

    mode = 'text' if args.to_text else 'binary' if args.to_binary else 'decompress'

    if args.analyze:
        analyze_file(args.analyze)
    elif args.file:
        result = convert_file(args.file[0], args.file[1], mode, args.format_version, True, args.add_refids)
        if result == 'copied':
            print(f'  {args.file[0]} is already in the target format; copied unchanged')
    elif args.in_place:
        process_directory(args.in_place, args.in_place, mode, args.format_version, args.verbose, args.add_refids)
    elif args.dir:
        process_directory(args.dir[0], args.dir[1], mode, args.format_version, args.verbose, args.add_refids)
    else:
        input_dir = 'Inf'
        output_dir = {'text': 'Inf_text', 'binary': 'Inf_binary', 'decompress': 'Inf_decompressed'}[mode]
        if not os.path.exists(input_dir):
            print(f"Error: '{input_dir}' folder not found; use -d to specify input/output directories")
            return
        process_directory(input_dir, output_dir, mode, args.format_version, args.verbose, args.add_refids)


if __name__ == '__main__':
    main()
