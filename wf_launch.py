"""War Front: Turning Point launcher that patches the game in memory.

  --editor      start the built-in "CoE" level editor instead of the game
                (swaps the hard-coded app-mode string "game" -> "editor")
  --debug-mode  EXPERIMENTAL / untested: set the game's Debug Mode flag
                (same flag as the editor's Tools > Debug Mode)

The retail exe is encrypted on disk, so it cannot be patched as a file; this
launcher waits until the code is decrypted in memory and patches it before the
start-up code reaches the patch site. The build is recognised by the original
bytes at the patch site; unknown builds are refused.

Usage: python wf_launch.py "C:\\Games\\War Front\\WarFront.exe" --editor
"""
import argparse, ctypes, ctypes.wintypes as wt, os, struct, subprocess, sys, time

BUILDS = {
    # name: (push "game" addr, original 5 bytes, "editor" string addr, gameApp global)
    "retail_hun": (0x7AE0A3, bytes.fromhex("68e41dbf00"), 0xC1FD54, 0xE891B8),
    "spdemo_1.01": (0x7AA363, bytes.fromhex("684cedbe00"), 0xC1CCC4, 0xE86E90),
}

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, ctypes.POINTER(wt.DWORD)]


def rpm(h, addr, n):
    buf = ctypes.create_string_buffer(n); got = ctypes.c_size_t()
    return buf.raw if k32.ReadProcessMemory(h, addr, buf, n, ctypes.byref(got)) and got.value == n else None


def wpm(h, addr, b):
    old = wt.DWORD()
    k32.VirtualProtectEx(h, addr, len(b), 0x40, ctypes.byref(old))
    ok = k32.WriteProcessMemory(h, addr, b, len(b), None)
    k32.VirtualProtectEx(h, addr, len(b), old.value, ctypes.byref(old))
    return bool(ok)


def detect(h):
    for name, (addr, orig, _, _) in BUILDS.items():
        if rpm(h, addr, 5) == orig:
            return name
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe", help="path to WarFront.exe")
    ap.add_argument("--editor", action="store_true")
    ap.add_argument("--debug-mode", action="store_true")
    ap.add_argument("--timeout", type=float, default=30)
    a = ap.parse_args()

    p = subprocess.Popen([a.exe], cwd=os.path.dirname(os.path.abspath(a.exe)))
    h = k32.OpenProcess(0x0438, False, p.pid)  # VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFORMATION
    t0 = time.time()
    build = None
    while build is None:  # tight loop: patch right after the code is decrypted
        build = detect(h)
        if p.poll() is not None or time.time() - t0 > a.timeout:
            sys.exit("could not find the patch site (unknown build?)")
    addr, orig, editor_str, app_global = BUILDS[build]
    print("build:", build, "code ready after %.3fs" % (time.time() - t0))

    if a.editor:
        ok = wpm(h, addr + 1, struct.pack("<I", editor_str))
        print("editor patch:", "ok" if ok else "FAILED")

    if a.debug_mode:
        while p.poll() is None and time.time() - t0 < a.timeout + 60:
            ptr = rpm(h, app_global, 4)
            app = struct.unpack("<I", ptr)[0] if ptr else 0
            if app:
                time.sleep(3)  # let the constructor finish before flipping the flag
                ok = wpm(h, app + 0x10, b"\x01")
                print("debug mode flag:", "ok" if ok else "FAILED", hex(app + 0x10))
                break
            time.sleep(0.05)
    print("pid", p.pid)


if __name__ == "__main__":
    main()
