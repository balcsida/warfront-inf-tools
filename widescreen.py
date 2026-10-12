"""
WarFront: Turning Point widescreen interface patch generator

The game draws its 2D interface in a virtual 1024x768 space that is stretched
to the screen. Setting stub\\screensize\\virtualsizex in Local Settings.setting
to 768 * width / height keeps the interface in proportion, but every screen is
laid out for 1024 pixels and ends up on the left. This tool rewrites the Prism
UI screens (Inf/2Prism) for the wider virtual width:

- menus, dialogs and full-screen overlays are centred (4:3 with bars)
- the in-game HUD is anchored to the screen edges: minimap block on the left,
  unit info block on the right, command panel and top bar centred. The bottom
  panel background is a single 1024x263 image per faction, so it is cut into
  three images that are placed separately.
- full-width decorations (top bar, menu header and footer, dimming layers and
  the first-person scope overlay) are widened to the whole screen by
  repeating plain parts of the original image: the top bar's cable, the
  footer's metal bar, the header's black edges.

All new images are built from the game's own files, so the patch ships none.

Prism coordinates:
- A control's areas (c2DArea) are screen coordinates when the control is
  top-level or has Position = 1, and relative to the parent's origin when it
  has Position = 0.
- A control's origin is its first area; a control without areas has its
  parent's origin. Primitive positions are relative to the control's origin.
- Skin classes (one per faction) override control areas (cPrismControlSkin,
  TargetID = control name) and primitive geometry (cPrism*Skin, TargetID =
  "control\\primitive").
- Tooltips with PosAbsolute = 1 have a screen-space PosOffset.
"""

import argparse
import copy
import os
import re
import struct
import sys

from decompress_inf import (
    TEXT_ENCODING,
    compress,
    decompress,
    detect_format,
    parse_text,
    read_binary,
    to_text,
    write_binary,
)

BASE_WIDTH = 1024
VIRTUAL_HEIGHT = 768

# In-game overlays that stay at the left edge, next to the minimap
LEFT_SCREENS = {
    'floatingmessage.inf', 'gamescreen.inf', 'heroespanel.inf',
    'minimapscreen.inf', 'popupmessagepanel.inf',
}
HUD_SCREENS = LEFT_SCREENS | {'centralpanel.inf'}

# The bottom panel image: minimap block, command panel, unit info block
CENTRAL_BLOCK = 'centralblock_image'
CENTRAL_BLOCK_SIZE = (1024, 263)
CENTRAL_BLOCK_PIECES = (('left', 0, 206), ('center', 206, 818), ('right', 818, 1024))

# centralpanel.inf controls and primitives by anchor; everything else is centred
CENTRALPANEL_RIGHT = {
    'infoparent', 'common3', 'permsparent', 'special_video', 'ranklow_ctrl',
    'rankhigh_ctrl', 'ammo_ctrl', 'hero_skillpoint_ctrl', 'CountdownText',
    'CountdownTimeText', f'{CENTRAL_BLOCK}_right',
}
CENTRALPANEL_LEFT = {
    'menu_button', 'objectives_button', 'diplomacy_button', 'timemultiplier',
    f'{CENTRAL_BLOCK}_left', 'switch', 'finish_exploring',
}
# Sell, production loop and repair buttons on the command panel's right edge
CENTRALPANEL_CENTER = {'commandslot4', 'commandslot5', 'commandslot6'}

# Top bar: the cable repeats every 120 pixels from x = 35; the thin bar on the
# right is plain in its last 16 columns
ROPE_START, ROPE_PERIOD = 35, 120
TOPBAR_TILE = (1008, 1024)
# Menu footer: metal bar mirrored from the 100 columns inside each 230-pixel end
FOOTER_CUT, FOOTER_PERIOD = 230, 100
# Scope overlay: plain grunge right of the scope, inside the darkened edges
OVERLAY_EDGE, OVERLAY_STRIP = 24, 110
# Menu header: black band, extended with columns next to its edges
HEADER_EDGE = 20


def virtual_width(width, height):
    return round(VIRTUAL_HEIGHT * width / height)


# ---------------------------------------------------------------------------
# Tree helpers
# ---------------------------------------------------------------------------

def get(node, key, default=None):
    for name, values in node.props:
        if name == key:
            return values
    return default


def get1(node, key, default=None):
    values = get(node, key)
    return values[0] if values else default


def set_prop(node, key, values):
    for i, (name, _) in enumerate(node.props):
        if name == key:
            node.props[i] = (name, values)
            return
    raise KeyError(key)


def section(node, name):
    for child in node.children:
        if child.name == name:
            return child.children
    return []


def class_name(node):
    return node.name.rsplit(':', 1)[-1].strip() if node.name else ''


def walk_nodes(node):
    yield node
    for child in node.children:
        yield from walk_nodes(child)


def shift_x(node, key, dx):
    x, *rest = get(node, key)
    set_prop(node, key, [x + dx, *rest])


# ---------------------------------------------------------------------------
# Screen-space coordinates
# ---------------------------------------------------------------------------

def screen_anchors(screen):
    """Yield (path, node, key) for every coordinate that is in screen space.

    path is the list of control names leading to the coordinate, ending with
    the primitive name for primitive positions.
    """
    skin_areas = {}
    skin_prims = {}
    for skin_class in section(screen, 'SkinClasses *'):
        for entry in section(skin_class, 'Parameters *'):
            target = get1(entry, 'TargetID', '')
            if class_name(entry) == 'cPrismControlSkin':
                skin_areas.setdefault(target, []).extend(section(entry, 'Areas *'))
            elif '\\' in target:
                control, prim = target.split('\\', 1)
                skin_prims.setdefault(control, []).append((prim, entry))

    seen = set()

    def emit(path, node, key):
        if id(node) not in seen and get(node, key) is not None:
            seen.add(id(node))
            yield path, node, key

    def walk(node, path, screen_origin):
        for control in section(node, 'Childrens *') + section(node, 'Controls *'):
            name = get1(control, 'Name', '')
            control_path = path + [name]
            is_screen = screen_origin or get1(control, 'Position') == 1
            areas = section(control, 'Areas *') + skin_areas.get(name, [])
            if is_screen:
                for area in areas:
                    yield from emit(control_path, area, 'Pos')
                if not areas:
                    for prim in section(control, 'Primitives *'):
                        yield from emit(control_path + [get1(prim, 'Name', '')], prim, 'Pos')
                    for prim_name, entry in skin_prims.get(name, []):
                        yield from emit(control_path + [prim_name], entry, 'Pos')
            yield from walk(control, control_path, is_screen and not areas)

    yield from walk(screen, [], True)

    for node in walk_nodes(screen):
        if class_name(node) == 'cPrismToolTip' and get1(node, 'PosAbsolute') == 1:
            yield from emit(['<tooltip>'], node, 'PosOffset')


def centralpanel_anchor(path):
    if any(name in CENTRALPANEL_CENTER for name in path):
        return 'center'
    if any(name in CENTRALPANEL_RIGHT or name.startswith('selectionslot') for name in path):
        return 'right'
    if any(name in CENTRALPANEL_LEFT for name in path):
        return 'left'
    return 'center'


def widen_art(screen, width):
    """Make full-width images (WIDE_ART) cover the whole screen.

    Returns the set of WIDE_ART images the screen uses.
    """
    used = set()
    skins = [(None, [])] + [(get1(c, 'Name'), section(c, 'Parameters *'))
                            for c in section(screen, 'SkinClasses *')]
    for skin, entries in skins:
        skin_areas = {get1(e, 'TargetID'): section(e, 'Areas *') for e in entries
                      if class_name(e) == 'cPrismControlSkin' and section(e, 'Areas *')}
        origins = {}

        def walk(node, parent_origin, top):
            for control in section(node, 'Childrens *') + section(node, 'Controls *'):
                name = get1(control, 'Name', '')
                base = 0 if top or get1(control, 'Position') == 1 else parent_origin
                areas = skin_areas.get(name) or section(control, 'Areas *')
                origin = base + get(areas[0], 'Pos')[0] if areas else base
                origins.setdefault(name, origin)
                if skin is None:
                    for prim in section(control, 'Primitives *'):
                        widen_prim(prim, origin)
                walk(control, origin, False)

        def widen_prim(prim, origin):
            image = (get1(prim, 'ImageName') or '').replace('\\', '/').lower()
            if image not in WIDE_ART or get(prim, 'Size')[0] != BASE_WIDTH:
                return
            set_prop(prim, 'Pos', [float(-origin), *get(prim, 'Pos')[1:]])
            set_prop(prim, 'Size', [float(width), *get(prim, 'Size')[1:]])
            if WIDE_ART[image]:
                set_prop(prim, 'ImageName', [wide_name(get1(prim, 'ImageName'))])
            used.add(image)

        walk(screen, 0, True)
        for entry in entries:
            target = get1(entry, 'TargetID', '')
            if '\\' in target and get(entry, 'ImageName') and target.split('\\')[0] in origins:
                widen_prim(entry, origins[target.split('\\')[0]])
    return used


def anchor_for(filename, path):
    if path == ['<tooltip>']:
        return 'right' if filename in HUD_SCREENS else 'center'
    if filename in LEFT_SCREENS:
        return 'left'
    if filename == 'centralpanel.inf':
        return centralpanel_anchor(path)
    return 'center'


# ---------------------------------------------------------------------------
# Bottom panel split
# ---------------------------------------------------------------------------

def split_central_block(screen):
    """Replace the 1024-wide bottom panel image with three pieces.

    The pieces keep their 4:3 positions; the anchor rules move them. Returns
    [(source image, x0, x1, piece image)] for the images to cut.
    """
    panel = next(c for c in section(screen, 'Controls *') if get1(c, 'Name') == 'centralpanel')
    prims = section(panel, 'Primitives *')
    index = next(i for i, p in enumerate(prims) if get1(p, 'Name') == CENTRAL_BLOCK)
    next_refid = 1 + max(int(get1(n, '_RefID', 0)) for n in walk_nodes(screen))
    for offset, (piece, _, _) in enumerate(p for p in CENTRAL_BLOCK_PIECES if p[0] != 'center'):
        prim = copy.deepcopy(prims[index])
        set_prop(prim, 'Name', [f'{CENTRAL_BLOCK}_{piece}'])
        set_prop(prim, '_RefID', [float(next_refid + offset)])
        prims.insert(index + 1 + offset, prim)

    crops = []
    for skin_class in section(screen, 'SkinClasses *'):
        entries = section(skin_class, 'Parameters *')
        target = f'centralpanel\\{CENTRAL_BLOCK}'
        for entry in list(entries):
            if get1(entry, 'TargetID') != target:
                continue
            image = get1(entry, 'ImageName')
            x, y = get(entry, 'Pos')
            if (x, *get(entry, 'Size')) != (0, *CENTRAL_BLOCK_SIZE):
                raise ValueError(f'unexpected {target} geometry in skin {get1(skin_class, "Name")}')
            base, ext = os.path.splitext(image)
            for piece, x0, x1 in CENTRAL_BLOCK_PIECES:
                piece_entry = entry if piece == 'center' else copy.deepcopy(entry)
                piece_image = f'{base}_{piece}{ext}'
                if piece != 'center':
                    set_prop(piece_entry, 'TargetID', [f'{target}_{piece}'])
                    entries.insert(entries.index(entry) + 1, piece_entry)
                set_prop(piece_entry, 'Pos', [float(x0), y])
                set_prop(piece_entry, 'Size', [float(x1 - x0), CENTRAL_BLOCK_SIZE[1]])
                set_prop(piece_entry, 'ImageName', [piece_image])
                crops.append((image, x0, x1, piece_image))
    return crops


def is_patched(screen):
    return any(get1(n, 'Name') == f'{CENTRAL_BLOCK}_left' for n in walk_nodes(screen))


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

class Tga:
    """An uncompressed 32-bit TGA image as rows of raw BGRA pixels."""

    def __init__(self, header, width, rows):
        self.header, self.width, self.rows = header, width, rows

    @classmethod
    def load(cls, data):
        id_length, colormap_type, image_type = data[0], data[1], data[2]
        width, height, bits, descriptor = struct.unpack_from('<HHBB', data, 12)
        if colormap_type or image_type != 2 or bits != 32 or descriptor & 0x10:
            raise ValueError('only uncompressed left-to-right 32-bit TGA images are supported')
        header = bytearray(data[:18])
        header[0] = 0
        start = 18 + id_length
        row = width * 4
        return cls(header, width, [data[start + y * row:start + (y + 1) * row] for y in range(height)])

    def remap(self, columns):
        """New image whose column i is this image's column columns[i]."""
        rows = [b''.join(row[c * 4:c * 4 + 4] for c in columns) for row in self.rows]
        return Tga(self.header, len(columns), rows)

    def dump(self):
        header = bytearray(self.header)
        struct.pack_into('<H', header, 12, self.width)
        return bytes(header) + b''.join(self.rows)


def pingpong(anchor, step, period, count):
    """`count` columns that start and end at `anchor`, mirroring back and forth
    over `period` columns in direction `step` (so every seam is continuous)."""
    cycles = max(1, round(count / (2 * period)))
    columns = []
    for i in range(count):
        phase = i * 2 * cycles / max(count - 1, 1) % 2
        columns.append(anchor + step * round(min(phase, 2 - phase) * (period - 1)))
    return columns


def topbar_columns(width, left, right):
    """Repeat the cable to the left edge and the thin bar to the right edge."""
    start = left + ROPE_START
    cable = [ROPE_START + (i - start) % ROPE_PERIOD for i in range(start)]
    tile = range(*TOPBAR_TILE)
    return cable + list(range(ROPE_START, width)) + [tile[i % len(tile)] for i in range(right)]


def footer_columns(width, left, right):
    """Keep both ends and the centre, mirror the metal bar in between."""
    return (list(range(FOOTER_CUT)) + pingpong(FOOTER_CUT - 1, -1, FOOTER_PERIOD, left)
            + list(range(FOOTER_CUT, width - FOOTER_CUT))
            + pingpong(width - FOOTER_CUT, 1, FOOTER_PERIOD, right)
            + list(range(width - FOOTER_CUT, width)))


def overlay_columns(width, left, right):
    """Replace the darkened edges and fill both sides with the plain grunge
    strip right of the scope (the left side has a second, smaller circle)."""
    anchor = width - 1 - OVERLAY_EDGE
    fill_left = pingpong(anchor, -1, OVERLAY_STRIP, left + OVERLAY_EDGE)[::-1]
    fill_right = pingpong(anchor, -1, OVERLAY_STRIP, right + OVERLAY_EDGE)
    return fill_left + list(range(OVERLAY_EDGE, anchor + 1)) + fill_right


def edge_columns(width, left, right):
    """Extend with the columns next to the left and right edges."""
    return [HEADER_EDGE] * left + list(range(width)) + [width - 1 - HEADER_EDGE] * right


# Images widened to the full screen width, by lowercase game path. None means
# a plain fill that is stretched instead.
WIDE_ART = {
    'gfx/interface/common/common/bg.tga': None,
    'gfx/interface/common/common/header.tga': edge_columns,
    'gfx/interface/common/common/footer.tga': footer_columns,
    'gfx/interface/common/fpspanel/fpsmode.tga': overlay_columns,
    'gfx/interface/common/centralpanel/felsocsik_ger.tga': topbar_columns,
    'gfx/interface/common/centralpanel/felsocsik_us.tga': topbar_columns,
    'gfx/interface/common/centralpanel/felsocsik_rus.tga': topbar_columns,
}


def wide_name(image):
    base, ext = os.path.splitext(image)
    return f'{base}_wide{ext}'


def widen_image(data, columns_for, width):
    """Build the `width`-pixel version of an image, centred like the screens."""
    image = Tga.load(data)
    left = (width - image.width) // 2
    return image.remap(columns_for(image.width, left, width - image.width - left)).dump()


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def find_path(base, relative):
    """Resolve a game-relative path case-insensitively, like Windows does."""
    path = base
    for part in re.split(r'[\\/]+', relative):
        if not part:
            continue
        names = {name.lower(): name for name in os.listdir(path)}
        if part.lower() not in names:
            raise FileNotFoundError(os.path.join(path, part))
        path = os.path.join(path, names[part.lower()])
    return path


def read_inf(path):
    with open(path, 'rb') as f:
        data = f.read()
    kind = detect_format(data)
    if kind == 'text':
        return parse_text(data.decode(TEXT_ENCODING)), 3
    if kind == 'compressed':
        raw, version = decompress(data)
        return read_binary(raw, version)
    if kind == 'binary':
        return read_binary(data)
    raise ValueError(f'{path}: unrecognised format')


def write_inf(path, root, version, text):
    data = to_text(root).encode(TEXT_ENCODING) if text else compress(write_binary(root, version), version)
    with open(path, 'wb') as f:
        f.write(data)


def read_settings(path):
    settings = {}
    with open(path, encoding=TEXT_ENCODING) as f:
        for line in f:
            match = re.match(r'(\S+)\s*=\s*(?:num|str) ?(.*?)\r?$', line)
            if match:
                settings[match.group(1).lower()] = match.group(2)
    return settings


def build_patch(game_dir, output_dir, width, text=False, inf_dir=None):
    """Write the patched screens and images for virtual width `width`.

    The original INF files are read from inf_dir (default: the game's Inf).
    """
    extra = width - BASE_WIDTH
    offsets = {'left': 0, 'center': extra // 2, 'right': extra}
    prism_dir = find_path(inf_dir or find_path(game_dir, 'Inf'), '2Prism')
    out_prism = os.path.join(output_dir, 'Inf', os.path.basename(prism_dir))
    os.makedirs(out_prism, exist_ok=True)

    written = 0
    crops = []
    wide = set()
    for filename in sorted(os.listdir(prism_dir)):
        if not filename.lower().endswith('.inf'):
            continue
        root, version = read_inf(os.path.join(prism_dir, filename))
        screen = root.children[0] if root.children else None
        if screen is None or class_name(screen) != 'cPrismScreen':
            continue
        key = filename.lower()
        changed = False
        if key == 'centralpanel.inf':
            if is_patched(screen):
                raise ValueError(f'{filename} is already patched; use --inf to point at the original files')
            crops = split_central_block(screen)
            changed = True

        for path, node, prop in screen_anchors(screen):
            dx = offsets[anchor_for(key, path)]
            if dx:
                shift_x(node, prop, dx)
                changed = True
        used = widen_art(screen, width)
        wide |= used
        if changed or used:
            write_inf(os.path.join(out_prism, filename), root, version, text)
            written += 1

    images = [(image, piece_image, lambda data, x0=x0, x1=x1: Tga.load(data).remap(range(x0, x1)).dump())
              for image, x0, x1, piece_image in crops]
    images += [(image, wide_name(image), lambda data, image=image: widen_image(data, WIDE_ART[image], width))
               for image in sorted(wide) if WIDE_ART[image]]
    for image, new_image, build in images:
        source = find_path(game_dir, image)
        target = os.path.join(output_dir, os.path.relpath(os.path.dirname(source), game_dir),
                              os.path.basename(new_image))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(source, 'rb') as f:
            data = build(f.read())
        with open(target, 'wb') as f:
            f.write(data)
    return written, len(images)


def main(argv=None, prog=None):
    parser = argparse.ArgumentParser(
        prog=prog, description='Generate a widescreen interface patch for WarFront: Turning Point')
    parser.add_argument('game_dir', help='game folder with the original Inf and Gfx folders')
    parser.add_argument('-r', '--resolution', metavar='WIDTHxHEIGHT',
                        help='screen resolution (default: activesizex/y from Local Settings.setting)')
    parser.add_argument('-o', '--output', help='output folder (default: widescreen_<width>x<height>)')
    parser.add_argument('--inf', metavar='DIR',
                        help='folder with the original INF files (default: the game\'s Inf folder)')
    parser.add_argument('--text', action='store_true', help='write text INF files instead of binary')
    args = parser.parse_args(argv)

    if args.resolution:
        match = re.fullmatch(r'(\d+)[xX:](\d+)', args.resolution)
        if not match:
            parser.error('resolution must look like 2560x1080')
        width, height = int(match.group(1)), int(match.group(2))
    else:
        settings = read_settings(find_path(args.game_dir, 'Local Settings.setting'))
        width = int(float(settings['stub\\screensize\\activesizex']))
        height = int(float(settings['stub\\screensize\\activesizey']))

    vwidth = virtual_width(width, height)
    if vwidth <= BASE_WIDTH:
        parser.error(f'{width}x{height} is not wider than 4:3')
    output_dir = args.output or f'widescreen_{width}x{height}'

    try:
        screens, images = build_patch(args.game_dir, output_dir, vwidth, args.text, args.inf)
    except (OSError, ValueError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1

    print(f'{width}x{height}: virtual interface width {vwidth}')
    print(f'Wrote {screens} screens and {images} images to {output_dir}')
    print('\nTo install:')
    print(f'  1. Copy the contents of {output_dir} over the game folder (back up Inf first).')
    print('  2. In Local Settings.setting set:')
    print(f'       stub\\screensize\\virtualsizex                       = num {vwidth}')
    print('       stub\\screensize\\virtualsizey                       = num 768')
    return 0


if __name__ == '__main__':
    sys.exit(main())
