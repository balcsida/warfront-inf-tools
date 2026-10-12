"""
WarFront: Turning Point editor unlock and debug mode

WarFront.exe contains Digital Reality's full level editor (window title
"CoE"), but the start-up code hard-codes the application mode:

    push offset "game"          ; appModeName = "game"
    ...                         ; isEditor = strcmp(appModeName, "editor") == 0

The editor and GUI editor modes are only registered when isEditor is true, so
pushing the address of the existing "editor" string instead starts the editor.
See docs/editor-unlock.md for the full write-up.

- The SP demo exe is not encrypted, so it can be patched on disk
  (patch_demo_exe).
- The retail exe is encrypted on disk and decrypts itself at start-up, so it
  is patched in memory right after decryption (launch, Windows only).

Debug Mode (the editor's Tools > Debug Mode) is one byte at gameApp+0x10. It
relaxes tech, research and production availability checks for the local
player in single-player games. launch(debug_mode=True) sets it without the
editor after checking that the object's get/set methods are the expected
accessors.
"""

import argparse
import collections
import os
import struct
import subprocess
import sys
import time

Build = collections.namedtuple('Build', 'name push_game original editor_string game_app')

BUILDS = [
    # push_game: VA of `push offset "game"`; original: its 5 bytes;
    # editor_string: VA of "editor"; game_app: global holding the game app object
    Build('retail_hun', 0x7AE0A3, bytes.fromhex('68e41dbf00'), 0xC1FD54, 0xE891B8),
    Build('spdemo_1.01', 0x7AA363, bytes.fromhex('684cedbe00'), 0xC1CCC4, 0xE86E90),
]
DEMO = BUILDS[1]

DEBUG_FLAG_OFFSET = 0x10
DEBUG_SETTER = bytes.fromhex('8a442404884110c20400')  # mov al,[esp+4]; mov [ecx+0x10],al; ret 4  (vtable+0x90)
DEBUG_GETTER = bytes.fromhex('8a4110c3')              # mov al,[ecx+0x10]; ret                    (vtable+0x94)


def patched_push(build):
    """The `push offset "editor"` instruction that replaces `push offset "game"`."""
    return b'\x68' + struct.pack('<I', build.editor_string)


def detect_build(read):
    """Return the Build whose patch site holds its original bytes, or None.

    read(address, size) returns bytes, or None if the memory is unreadable.
    """
    for build in BUILDS:
        if read(build.push_game, len(build.original)) == build.original:
            return build
    return None


def has_debug_accessors(read, obj):
    """True if obj's vtable get/set slots are the [this+0x10] byte accessors."""
    vtable = _read_u32(read, obj)
    setter = _read_u32(read, vtable + 0x90) if vtable else None
    getter = _read_u32(read, vtable + 0x94) if vtable else None
    return (setter is not None and getter is not None
            and read(setter, len(DEBUG_SETTER)) == DEBUG_SETTER
            and read(getter, len(DEBUG_GETTER)) == DEBUG_GETTER)


def _read_u32(read, address):
    data = read(address, 4)
    return struct.unpack('<I', data)[0] if data and len(data) == 4 else None


# --- SP demo: patch on disk ------------------------------------------------

def file_offset(data, va):
    """Map a virtual address to a file offset using the PE section table."""
    if data[:2] != b'MZ':
        raise ValueError('not a PE file')
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('not a PE file')
    sections = struct.unpack_from('<H', data, pe + 6)[0]
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    image_base = struct.unpack_from('<I', data, pe + 24 + 28)[0]
    rva = va - image_base
    table = pe + 24 + optional_size
    for i in range(sections):
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from('<IIII', data, table + i * 40 + 8)
        if virtual_address <= rva < virtual_address + raw_size:
            return raw_pointer + rva - virtual_address
    raise ValueError(f'address 0x{va:X} is not in the file')


def patch_demo_exe(source, output=None):
    """Write an editor-mode copy of the SP demo exe; return its path."""
    with open(source, 'rb') as f:
        data = bytearray(f.read())
    offset = file_offset(data, DEMO.push_game)
    if data[offset:offset + len(DEMO.original)] != DEMO.original:
        raise ValueError('unexpected bytes at the patch site; this is not the SP demo 1.01 WarFront.exe')
    data[offset:offset + len(DEMO.original)] = patched_push(DEMO)
    output = output or os.path.join(os.path.dirname(os.path.abspath(source)), 'WarFront_editor.exe')
    with open(output, 'wb') as f:
        f.write(data)
    return output


# --- Any build: patch in memory (Windows) ----------------------------------

class Process:
    """Read/write access to another process's memory through kernel32."""

    def __init__(self, pid):
        import ctypes
        from ctypes import wintypes as wt
        self._ctypes = ctypes
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        k32.OpenProcess.restype = wt.HANDLE
        k32.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t,
                                          ctypes.POINTER(ctypes.c_size_t)]
        k32.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t,
                                           ctypes.POINTER(ctypes.c_size_t)]
        k32.VirtualProtectEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD,
                                         ctypes.POINTER(wt.DWORD)]
        k32.CloseHandle.argtypes = [wt.HANDLE]
        self._k32 = k32
        self._dword = wt.DWORD
        # PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
        self.handle = k32.OpenProcess(0x0438, False, pid)
        if not self.handle:
            raise OSError(f'cannot open process {pid}')

    def read(self, address, size):
        ctypes = self._ctypes
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t()
        ok = self._k32.ReadProcessMemory(self.handle, address, buf, size, ctypes.byref(got))
        return buf.raw if ok and got.value == size else None

    def write(self, address, data):
        old = self._dword()
        self._k32.VirtualProtectEx(self.handle, address, len(data), 0x40, self._ctypes.byref(old))  # RWX
        ok = self._k32.WriteProcessMemory(self.handle, address, data, len(data), None)
        self._k32.VirtualProtectEx(self.handle, address, len(data), old.value, self._ctypes.byref(old))
        return bool(ok) and self.read(address, len(data)) == data

    def close(self):
        self._k32.CloseHandle(self.handle)


def launch(exe, editor=False, debug_mode=False, timeout=30, log=print):
    """Start WarFront.exe, apply the in-memory patches and return the process id."""
    if os.name != 'nt':
        raise OSError('launching the game is only supported on Windows')
    process = subprocess.Popen([exe], cwd=os.path.dirname(os.path.abspath(exe)))
    memory = Process(process.pid)
    try:
        start = time.time()
        build = None
        while build is None:  # busy-wait: the patch must land before start-up reaches it
            build = detect_build(memory.read)
            if process.poll() is not None:
                raise RuntimeError('the game exited before its code could be patched')
            if time.time() - start > timeout:
                raise RuntimeError('patch site not found; unknown WarFront.exe build')
        log(f'build: {build.name} (code ready after {time.time() - start:.3f}s)')

        if editor:
            ok = memory.write(build.push_game, patched_push(build))
            log('editor mode: ' + ('patched' if ok else 'FAILED'))

        if debug_mode:
            app = None
            while not app:
                if process.poll() is not None or time.time() - start > timeout + 60:
                    raise RuntimeError('game app object not found')
                app = _read_u32(memory.read, build.game_app)
                time.sleep(0.05)
            time.sleep(3)  # let the constructor finish before setting the flag
            if not has_debug_accessors(memory.read, app):
                raise RuntimeError(f'object at 0x{app:X} does not look like the game app; flag not set')
            ok = memory.write(app + DEBUG_FLAG_OFFSET, b'\x01')
            log('debug mode: ' + (f'on (0x{app + DEBUG_FLAG_OFFSET:X} = 1)' if ok else 'FAILED'))
        return process.pid
    finally:
        memory.close()


# --- Command line ------------------------------------------------------------

def main_launch(argv=None, prog=None):
    parser = argparse.ArgumentParser(
        prog=prog, description='Start WarFront.exe with in-memory patches (Windows)')
    parser.add_argument('exe', help='path to WarFront.exe (retail or SP demo 1.01)')
    parser.add_argument('--editor', action='store_true', help='start the built-in CoE level editor')
    parser.add_argument('--debug-mode', action='store_true',
                        help='turn on Debug Mode (relaxed tech/production checks in single-player)')
    parser.add_argument('--timeout', type=float, default=30, help='seconds to wait for the patch site')
    args = parser.parse_args(argv)
    if not (args.editor or args.debug_mode):
        parser.error('nothing to do: give --editor and/or --debug-mode')
    try:
        pid = launch(args.exe, args.editor, args.debug_mode, args.timeout)
    except (OSError, RuntimeError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1
    print(f'pid {pid}')
    return 0


def main_patch_demo(argv=None, prog=None):
    parser = argparse.ArgumentParser(
        prog=prog, description='Write an editor-mode copy of the SP demo 1.01 WarFront.exe')
    parser.add_argument('exe', help='path to the SP demo WarFront.exe (not modified)')
    parser.add_argument('-o', '--output', help='output file (default: WarFront_editor.exe next to the input)')
    args = parser.parse_args(argv)
    try:
        output = patch_demo_exe(args.exe, args.output)
    except (OSError, ValueError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1
    print(f'Wrote {output}; run it from the game folder to start the editor')
    return 0
