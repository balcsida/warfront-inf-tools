import os
import struct
import tempfile
import unittest

from decompress_inf import Node
from widescreen import (
    FOOTER_CUT,
    OVERLAY_EDGE,
    ROPE_START,
    Tga,
    build_patch,
    edge_columns,
    footer_columns,
    get,
    get1,
    overlay_columns,
    pingpong,
    screen_anchors,
    topbar_columns,
    widen_art,
)


def area(x, y, w=10, h=10):
    return Node(': c2DArea', [('Pos', [float(x), float(y)]), ('Size', [float(w), float(h)])])


def prim(name, x, y, w=10, h=10, image=None):
    props = [('Name', [name]), ('Pos', [float(x), float(y)]), ('Size', [float(w), float(h)])]
    if image:
        props.append(('ImageName', [image]))
    return Node(': cPrismImagePrimitive', props)


def control(name, position, areas=(), prims=(), children=(), tooltip=None):
    nodes = [Node('Areas *', children=list(areas)), Node('Primitives *', children=list(prims)),
             Node('Childrens *', children=list(children))]
    if tooltip:
        nodes.append(tooltip)
    return Node(': cPrismControl', [('Name', [name]), ('Position', [float(position)])], nodes)


def screen(controls, skins=()):
    return Node(': cPrismScreen', [('Name', ['Test'])], [
        Node('Controls *', children=list(controls)),
        Node('SkinClasses *', children=[
            Node(': cPrismSkinClass', [('Name', [skin])], [Node('Parameters *', children=entries)])
            for skin, entries in skins]),
    ])


class ScreenAnchorTests(unittest.TestCase):
    def test_position_rules(self):
        tooltip = Node('ToolTip : cPrismToolTip', [('PosAbsolute', [1.0]), ('PosOffset', [818.0, 404.0])])
        scr = screen([
            control('top', 1, [area(100, 0)], [prim('top_prim', 1, 1)], [
                control('relative', 0, [area(10, 10)]),
                control('absolute', 1, [area(500, 0)], tooltip=tooltip),
            ]),
            control('no_area', 1, prims=[prim('screen_prim', 900, 0)], children=[
                control('inherits_screen', 0, [area(20, 20)]),
            ]),
        ], skins=[('GERMAN', [
            Node(': cPrismControlSkin', [('TargetID', ['relative'])], [Node('Areas *', children=[area(11, 11)])]),
            Node(': cPrismPrimitiveImageSkin', [('TargetID', ['no_area\\screen_prim']),
                                                ('Pos', [901.0, 0.0])]),
        ])])

        anchors = sorted(('/'.join(path), get(node, key)) for path, node, key in screen_anchors(scr))
        self.assertEqual(anchors, [
            ('<tooltip>', [818.0, 404.0]),
            ('no_area/inherits_screen', [20.0, 20.0]),
            ('no_area/screen_prim', [900.0, 0.0]),
            ('no_area/screen_prim', [901.0, 0.0]),  # skin override
            ('top', [100.0, 0.0]),
            ('top/absolute', [500.0, 0.0]),
        ])

    def test_widen_art_covers_the_screen(self):
        image = 'gfx/interface/common/common/header.tga'
        scr = screen([control('common', 1, [area(398, 0, 1024, 210)], [prim('bgimage', 0, 0, 1024, 210, image)])])
        self.assertEqual(widen_art(scr, 1820), {image})
        header = scr.children[0].children[0].children[1].children[0]
        self.assertEqual(get(header, 'Pos'), [-398.0, 0.0])
        self.assertEqual(get(header, 'Size'), [1820.0, 210.0])
        self.assertEqual(get1(header, 'ImageName'), 'gfx/interface/common/common/header_wide.tga')


class ColumnMapTests(unittest.TestCase):
    def test_pingpong_starts_and_ends_at_anchor(self):
        for count in (1, 2, 57, 398, 1000):
            with self.subTest(count=count):
                columns = pingpong(999, -1, 110, count)
                self.assertEqual(len(columns), count)
                self.assertEqual((columns[0], columns[-1]), (999, 999))
                self.assertTrue(all(890 <= c <= 999 for c in columns))

    def test_original_stays_centred(self):
        builders = {
            edge_columns: range(0, 1024),
            footer_columns: range(FOOTER_CUT, 1024 - FOOTER_CUT),
            topbar_columns: range(ROPE_START, 1024),
            overlay_columns: range(OVERLAY_EDGE, 1024 - OVERLAY_EDGE),
        }
        for width in (1229, 1365, 1820):
            left = (width - 1024) // 2
            for build, kept in builders.items():
                with self.subTest(width=width, builder=build.__name__):
                    columns = build(1024, left, width - 1024 - left)
                    self.assertEqual(len(columns), width)
                    self.assertEqual([columns[left + x] for x in kept], list(kept))
                    self.assertTrue(all(0 <= c < 1024 for c in columns))


class TgaTests(unittest.TestCase):
    def test_remap_columns(self):
        header = bytes([0, 0, 2]) + bytes(9) + struct.pack('<HHBB', 3, 2, 32, 8)
        pixels = bytes(range(24))
        image = Tga.load(header + pixels).remap([2, 0])
        self.assertEqual(image.dump(), header[:12] + struct.pack('<HHBB', 2, 2, 32, 8)
                         + pixels[8:12] + pixels[0:4] + pixels[20:24] + pixels[12:16])

    def test_rejects_compressed_images(self):
        header = bytes([0, 0, 10]) + bytes(9) + struct.pack('<HHBB', 1, 1, 32, 8)
        with self.assertRaises(ValueError):
            Tga.load(header + bytes(4))


GAME_DIR = os.environ.get('WARFRONT_DIR')
INF_DIR = os.environ.get('WARFRONT_INF_DIR')  # original Inf, if the game's Inf is patched


@unittest.skipUnless(GAME_DIR, 'set WARFRONT_DIR to a game install to build a patch')
class BuildPatchTests(unittest.TestCase):
    def test_build_and_refuse_to_patch_twice(self):
        with tempfile.TemporaryDirectory() as out:
            screens, images = build_patch(GAME_DIR, out, 1820, inf_dir=INF_DIR)
            self.assertGreater(screens, 40)
            self.assertEqual(images, 9 + 6)
            with self.assertRaises(ValueError):
                build_patch(GAME_DIR, os.path.join(out, 'again'), 1820, inf_dir=os.path.join(out, 'Inf'))


if __name__ == '__main__':
    unittest.main()
