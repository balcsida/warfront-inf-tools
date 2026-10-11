import glob
import os
import struct
import unittest

from decompress_inf import (
    Node,
    TextFormatError,
    WString,
    add_refids,
    binary_to_text,
    compress,
    decompress,
    detect_format,
    parse_text,
    read_binary,
    text_to_binary,
    write_binary,
)


def u32(value):
    return struct.pack("<I", value)


class BinaryBuilder:
    """Hand-assembles decompressed binary INF data for tests."""

    def __init__(self, index_size=4):
        self.index_size = index_size
        self.body = bytearray()

    def idx(self, value):
        self.body += value.to_bytes(self.index_size, "little")
        return self

    def raw(self, data):
        self.body += data
        return self

    def prop(self, name_idx, *values):
        self.idx(name_idx)
        self.body.append(len(values))
        for value_type, value in values:
            self.body.append(value_type)
            if value_type == 1:
                self.body += struct.pack("<d", value)
            else:
                self.idx(value)
        return self

    def node(self, name_idx, prop_count, child_count):
        return self.idx(name_idx).raw(u32(prop_count) + u32(child_count))

    def build(self, root_props, root_children, strings, wstrings=()):
        data = bytearray(u32(0) + u32(root_props) + u32(root_children) + self.body)
        data[0:4] = u32(len(data))
        data += u32(len(strings))
        for s in strings:
            data += s.encode("ascii") + b"\x00"
        data += u32(len(wstrings))
        for s in wstrings:
            data += u32(len(s)) + s.encode("utf-16le")
        return bytes(data)


class ReadBinaryTests(unittest.TestCase):
    def test_multiple_top_level_sections(self):
        # Layout of defaultmusics.inf / terrainmaps.inf
        strings = ["Root", "type", "WordMap", "Other", "Value"]
        b = BinaryBuilder()
        b.node(0, 1, 0).prop(1, (0, 2))
        b.node(3, 1, 0).prop(4, (1, 42.0))
        data = b.build(0, 2, strings)

        self.assertEqual(
            binary_to_text(data),
            "[Root]\r\n"
            "{\r\n"
            "\ttype = \"WordMap\"\r\n"
            "}\r\n"
            "\r\n"
            "[Other]\r\n"
            "{\r\n"
            "\tValue = 42\r\n"
            "}\r\n",
        )

    def test_object_with_container_and_inline_sections(self):
        strings = ["PRGAME : cPRGame", "_RefID", "Title", "Root Title", "Items *",
                   ": cThing", "Name", "Thing One", "Tip : cTip"]
        b = BinaryBuilder()
        b.node(0, 2, 2).prop(1, (1, 1.0)).prop(2, (0, 3))
        b.node(4, 0, 1)              # container
        b.node(5, 1, 0).prop(6, (0, 7))
        b.node(8, 0, 0)              # inline section with no properties
        data = b.build(0, 1, strings)

        self.assertEqual(
            binary_to_text(data),
            "[PRGAME : cPRGame]\r\n"
            "{\r\n"
            "\t_RefID = 1\r\n"
            "\tTitle = \"Root Title\"\r\n"
            "\r\n"
            "\t[Items *]\r\n"
            "\t{\r\n"
            "\r\n"
            "\t\t[: cThing]\r\n"
            "\t\t{\r\n"
            "\t\t\tName = \"Thing One\"\r\n"
            "\t\t}\r\n"
            "\t}\r\n"
            "\t[Tip : cTip]\r\n"
            "\t{\r\n"
            "\t}\r\n"
            "}\r\n",
        )

    def test_root_properties_before_sections(self):
        # Layout of terraintypetable.inf: a root property, then a container
        strings = ["StringID", "", "TerrainTypes *", ": cTerrainTypeItem", "Name",
                   "#0;0 - Human", "TrackColorMultiplier"]
        b = BinaryBuilder()
        b.prop(0, (0, 1))
        b.node(2, 0, 1)
        b.node(3, 2, 0).prop(4, (0, 5)).prop(6, *[(1, 255.0)] * 4)
        text = binary_to_text(b.build(1, 1, strings))

        self.assertTrue(text.startswith('StringID = ""\r\n\r\n[TerrainTypes *]\r\n'))
        self.assertIn('\t\tName = "#0;0 - Human"\r\n', text)
        self.assertIn("\t\tTrackColorMultiplier = 255, 255, 255, 255\r\n", text)

    def test_version_2_uses_16_bit_string_indices(self):
        strings = ["Effect", "Scale", "Texture", "smoke.dds"]
        b = BinaryBuilder(index_size=2)
        b.node(0, 2, 0).prop(1, (1, 1.5)).prop(2, (0, 3))
        raw = b.build(0, 1, strings)

        root, version = read_binary(raw)
        self.assertEqual(version, 2)
        self.assertEqual(root.children[0].props, [("Scale", [1.5]), ("Texture", ["smoke.dds"])])

        compressed = compress(raw, version=2)
        self.assertEqual(compressed[:4], b"\xAB\xA5\xFF\xFF")
        self.assertEqual(text_to_binary(binary_to_text(compressed), version=2), compressed)

    def test_wide_strings(self):
        b = BinaryBuilder()
        b.node(0, 1, 0).prop(1, (2, 0))
        data = b.build(0, 1, ["Profile", "PlayerName"], wstrings=["Játékos"])

        text = binary_to_text(data)
        self.assertIn('PlayerName = L"Játékos"', text)
        self.assertEqual(text_to_binary(text, compressed=False), data)

    def test_rejects_trailing_garbage(self):
        b = BinaryBuilder()
        b.node(0, 0, 0)
        data = b.build(0, 1, ["Root"]) + b"\x00"
        self.assertIsNone(detect_format(data))


class RoundTripTests(unittest.TestCase):
    def test_binary_text_binary_is_byte_exact(self):
        root = Node(children=[
            Node("A : cA", [("_RefID", [1.0]), ("S", ["x y"]), ("N", [-0.0, 0.1, -3.0, 1e20])], [
                Node("Items *", children=[Node(": cB", [("S", ["x y"]), ("W", [WString("w")])])]),
            ]),
        ])
        raw = write_binary(root)
        compressed = compress(raw)
        self.assertEqual(decompress(compressed), (raw, 3))
        self.assertEqual(read_binary(raw)[0], root)
        self.assertEqual(text_to_binary(binary_to_text(compressed)), compressed)

    def test_strings_are_numbered_in_first_use_order(self):
        raw = write_binary(Node(children=[Node("R", [("a", ["b", "a"]), ("c", ["b"])])]))
        table = raw[struct.unpack_from("<I", raw)[0]:]
        self.assertEqual(table, u32(4) + b"R\x00a\x00b\x00c\x00" + u32(0))


class ParseTextTests(unittest.TestCase):
    def test_developer_text_syntax(self):
        root = parse_text(
            "; comment\r\n"
            "\r\n"
            "[: cUnit]\r\n"
            "{\r\n"
            "\tUnit = axh_Hartman\r\n"
            "\tPos=1.5,-2, 3e2\r\n"
            '\tPath = "GFX\\objects\\Grass\\"\r\n'
            '\tMixed = "a, b", 7, L"wide"\r\n'
            "\tEmpty = \r\n"
            "}\r\n"
        )
        self.assertEqual(root.children[0].props, [
            ("Unit", ["axh_Hartman"]),
            ("Pos", [1.5, -2.0, 300.0]),
            ("Path", ["GFX\\objects\\Grass\\"]),
            ("Mixed", ["a, b", 7.0, WString("wide")]),
            ("Empty", []),
        ])
        self.assertIsInstance(root.children[0].props[3][1][2], WString)

    def test_errors(self):
        for text in ["[A]\r\n{\r\n", "}\r\n", "[A]\r\nx = 1\r\n", 'x = "open\r\n',
                     "#include \"x.inf\"\r\n", "#define\r\n", "# 1\r\n"]:
            with self.subTest(text=text):
                with self.assertRaises(TextFormatError):
                    parse_text(text)


class DefineTests(unittest.TestCase):
    def test_define_substitutes_values(self):
        root = parse_text(
            "#define TRUE 1\r\n"
            "#define FALSE 0\r\n"
            "#define REVERSE -1\r\n"
            "[Test]\r\n"
            "{\r\n"
            "\tCanFlash = FALSE\r\n"
            "\tDir = REVERSE\r\n"
            "\tPair = TRUE, FALSE\r\n"
            "}\r\n"
        )
        self.assertEqual(root.children[0].props, [
            ("CanFlash", [0.0]),
            ("Dir", [-1.0]),
            ("Pair", [1.0, 0.0]),
        ])

    def test_define_only_whole_words_outside_strings(self):
        root = parse_text(
            "#define HA_LEFT 0\r\n"
            "[Test]\r\n"
            "{\r\n"
            '\tName = "HA_LEFT"\r\n'
            '\tWide = L"HA_LEFT HA_LEFT"\r\n'
            "\tAlignment = HA_LEFT\r\n"
            "\tOther = HA_LEFTISH\r\n"
            "}\r\n"
        )
        self.assertEqual(root.children[0].props, [
            ("Name", ["HA_LEFT"]),
            ("Wide", [WString("HA_LEFT HA_LEFT")]),
            ("Alignment", [0.0]),
            ("Other", ["HA_LEFTISH"]),
        ])

    def test_define_applies_from_definition_point_on(self):
        root = parse_text(
            "[A]\r\n"
            "{\r\n"
            "\tV = X\r\n"
            "}\r\n"
            "#define X 5\r\n"
            "[B]\r\n"
            "{\r\n"
            "\tV = X\r\n"
            "}\r\n"
        )
        self.assertEqual(root.children[0].props, [("V", ["X"])])
        self.assertEqual(root.children[1].props, [("V", [5.0])])

    def test_redefine_last_wins(self):
        root = parse_text("#define X 1\r\n#define X 2\r\n[A]\r\n{\r\nV = X\r\n}\r\n")
        self.assertEqual(root.children[0].props, [("V", [2.0])])

    def test_file_with_only_defines_is_an_empty_tree(self):
        # GlobalIncludes.inf in the sales preview is all comments and defines
        root = parse_text("; comment\r\n#define SIMPLE 0\r\n\r\n#define LOOPED 1\r\n")
        self.assertEqual(root, Node())

    def test_define_in_section_header(self):
        root = parse_text("#define SEC MySection\r\n[SEC]\r\n{\r\n}\r\n")
        self.assertEqual(root.children[0].name, "MySection")

    def test_round_trip_through_binary(self):
        text = ("#define FALSE 0\r\n[Test]\r\n{\r\n\tCanFlash = FALSE\r\n}\r\n")
        root = parse_text(text)
        self.assertEqual(binary_to_text(text_to_binary(text)), "[Test]\r\n{\r\n\tCanFlash = 0\r\n}\r\n")
        self.assertEqual(root.children[0].props, [("CanFlash", [0.0])])


class AddRefIdsTests(unittest.TestCase):
    def test_numbers_root_objects_and_container_children(self):
        root = Node(children=[Node("G : cGame", [("X", [1.0])], [
            Node("Tip : cTip"),
            Node("Items *", children=[Node(": cA"), Node(": cB")]),
        ])])
        add_refids(root)
        game = root.children[0]
        self.assertEqual(game.props[0], ("_RefID", [1.0]))
        self.assertEqual(game.children[0].props, [])
        self.assertEqual([c.props for c in game.children[1].children],
                         [[("_RefID", [2.0])], [("_RefID", [3.0])]])

    def test_keeps_existing_refids(self):
        root = Node(children=[Node("G : cGame", [("_RefID", [7.0])], [Node("Items *", children=[Node(": cA")])])])
        add_refids(root)
        self.assertEqual(root.children[0].children[0].children[0].props, [])


GAME_DIR = os.environ.get("WARFRONT_DIR")


@unittest.skipUnless(GAME_DIR, "set WARFRONT_DIR to a game install to round-trip its INF files")
class GameFilesTests(unittest.TestCase):
    def test_all_binary_files_round_trip_byte_exact(self):
        count = 0
        for path in glob.glob(os.path.join(GAME_DIR, "**", "*.*"), recursive=True):
            if not path.lower().endswith((".inf", ".base")):
                continue
            with open(path, "rb") as f:
                data = f.read()
            kind = detect_format(data)
            if kind == "compressed":
                version = decompress(data)[1]
                with self.subTest(path=path):
                    self.assertEqual(text_to_binary(binary_to_text(data), version), data)
                count += 1
            elif kind == "binary":
                version = read_binary(data)[1]
                with self.subTest(path=path):
                    self.assertEqual(text_to_binary(binary_to_text(data), version, compressed=False), data)
                count += 1
        self.assertGreater(count, 0)


if __name__ == "__main__":
    unittest.main()
