import hashlib
import os
import struct
import tempfile
import unittest

from editor_unlock import (
    BUILDS,
    DEBUG_FLAG_OFFSET,
    DEBUG_GETTER,
    DEBUG_SETTER,
    DEMO,
    detect_build,
    file_offset,
    has_debug_accessors,
    patch_demo_exe,
    patched_push,
)


def fake_pe(sections, image_base=0x400000):
    """Minimal PE image: headers plus sections given as (virtual_address, raw_pointer, raw_bytes)."""
    pe = 0x80
    optional_size = 0xE0
    table = pe + 24 + optional_size
    size = max(raw + len(body) for _, raw, body in sections)
    data = bytearray(max(size, table + 40 * len(sections)))
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, pe)
    data[pe:pe + 4] = b'PE\0\0'
    struct.pack_into('<H', data, pe + 6, len(sections))
    struct.pack_into('<H', data, pe + 20, optional_size)
    struct.pack_into('<I', data, pe + 24 + 28, image_base)
    for i, (va, raw, body) in enumerate(sections):
        struct.pack_into('<IIII', data, table + i * 40 + 8, len(body), va, len(body), raw)
        data[raw:raw + len(body)] = body
    return bytes(data)


class FakeMemory:
    def __init__(self):
        self.bytes = {}

    def put(self, address, data):
        for i, b in enumerate(data):
            self.bytes[address + i] = b

    def read(self, address, size):
        if all(address + i in self.bytes for i in range(size)):
            return bytes(self.bytes[address + i] for i in range(size))
        return None


class BuildTests(unittest.TestCase):
    def test_patched_push_points_at_editor_string(self):
        for build in BUILDS:
            with self.subTest(build=build.name):
                push = patched_push(build)
                self.assertEqual(push[0], 0x68)
                self.assertEqual(len(push), len(build.original))
                self.assertEqual(struct.unpack('<I', push[1:])[0], build.editor_string)

    def test_detect_build(self):
        for build in BUILDS:
            with self.subTest(build=build.name):
                memory = FakeMemory()
                memory.put(build.push_game, build.original)
                self.assertEqual(detect_build(memory.read), build)

    def test_detect_unknown_or_encrypted(self):
        memory = FakeMemory()
        self.assertIsNone(detect_build(memory.read))
        memory.put(BUILDS[0].push_game, b'\x12\x34\x56\x78\x9a')  # still encrypted
        self.assertIsNone(detect_build(memory.read))

    def test_already_patched_is_not_detected(self):
        memory = FakeMemory()
        memory.put(DEMO.push_game, patched_push(DEMO))
        self.assertIsNone(detect_build(memory.read))


class DebugAccessorTests(unittest.TestCase):
    def setUp(self):
        self.memory = FakeMemory()
        self.app, vtable, setter, getter = 0x1000, 0x2000, 0x3000, 0x4000
        self.memory.put(self.app, struct.pack('<I', vtable))
        self.memory.put(vtable + 0x90, struct.pack('<I', setter))
        self.memory.put(vtable + 0x94, struct.pack('<I', getter))
        self.memory.put(setter, DEBUG_SETTER)
        self.memory.put(getter, DEBUG_GETTER)

    def test_accessors_found(self):
        self.assertTrue(has_debug_accessors(self.memory.read, self.app))
        self.assertIn(bytes([DEBUG_FLAG_OFFSET]), DEBUG_SETTER)

    def test_wrong_object_rejected(self):
        self.memory.put(0x4000, b'\x8a\x41\x14\xc3')  # getter for a different field
        self.assertFalse(has_debug_accessors(self.memory.read, self.app))
        self.assertFalse(has_debug_accessors(self.memory.read, 0x9999))  # unreadable


class DemoPatchTests(unittest.TestCase):
    TEXT_VA = DEMO.push_game & ~0xFFF

    def make_exe(self, site_bytes):
        body = bytearray(0x1000)
        site = DEMO.push_game - self.TEXT_VA
        body[site:site + len(site_bytes)] = site_bytes
        return fake_pe([(self.TEXT_VA - 0x400000, 0x400, bytes(body))])

    def test_file_offset(self):
        data = self.make_exe(DEMO.original)
        self.assertEqual(file_offset(data, DEMO.push_game), 0x400 + (DEMO.push_game - self.TEXT_VA))
        with self.assertRaises(ValueError):
            file_offset(data, 0x401000)
        with self.assertRaises(ValueError):
            file_offset(b'not a pe file' * 10, DEMO.push_game)

    def test_patch_writes_copy_and_keeps_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, 'WarFront.exe')
            original = self.make_exe(DEMO.original)
            with open(source, 'wb') as f:
                f.write(original)
            output = patch_demo_exe(source)
            self.assertEqual(output, os.path.join(tmp, 'WarFront_editor.exe'))
            with open(source, 'rb') as f:
                self.assertEqual(f.read(), original)
            with open(output, 'rb') as f:
                patched = f.read()
            offset = file_offset(patched, DEMO.push_game)
            self.assertEqual(patched[offset:offset + 5], patched_push(DEMO))
            self.assertEqual(patched[:offset] + patched[offset + 5:], original[:offset] + original[offset + 5:])

    def test_patch_refuses_unknown_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, 'WarFront.exe')
            with open(source, 'wb') as f:
                f.write(self.make_exe(patched_push(DEMO)))  # already patched
            with self.assertRaises(ValueError):
                patch_demo_exe(source, os.path.join(tmp, 'out.exe'))
            self.assertFalse(os.path.exists(os.path.join(tmp, 'out.exe')))


DEMO_EXE = os.environ.get('WARFRONT_DEMO_EXE')


@unittest.skipUnless(DEMO_EXE, 'set WARFRONT_DEMO_EXE to the SP demo 1.01 WarFront.exe')
class RealDemoTests(unittest.TestCase):
    def test_patch_real_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = patch_demo_exe(DEMO_EXE, os.path.join(tmp, 'WarFront_editor.exe'))
            with open(output, 'rb') as f:
                data = f.read()
            offset = file_offset(data, DEMO.push_game)
            self.assertEqual(offset, 0x3AA363)
            self.assertEqual(data[offset:offset + 5], bytes.fromhex('68c4ccc100'))
            with open(DEMO_EXE, 'rb') as f:
                self.assertEqual(hashlib.md5(f.read()).hexdigest(), '6292026fbd01f638741c052239d54628')


if __name__ == '__main__':
    unittest.main()
