"""Make an editor-mode copy of the War Front: Turning Point SP demo exe.

Writes WarFront_editor.exe next to WarFront.exe; the original is not modified.
Usage: python patch_spdemo.py "C:\\...\\spdemo\\Run\\WarFront.exe"
"""
import os, struct, sys

VA = 0x7AA363                      # push offset "game"  (stub init, app-mode selection)
ORIG = bytes.fromhex("684cedbe00")  # push 0x00BEED4C ("game")
EDITOR_STR = 0x00C1CCC4             # "editor"
FILE_OFF = VA - 0x401000 + 0x1000   # .text: VA 0x401000 -> raw 0x1000

src = sys.argv[1]
data = bytearray(open(src, "rb").read())
if data[FILE_OFF:FILE_OFF + 5] != ORIG:
    sys.exit("unexpected bytes at patch site - not the SP demo 1.01 exe?")
data[FILE_OFF + 1:FILE_OFF + 5] = struct.pack("<I", EDITOR_STR)
dst = os.path.join(os.path.dirname(os.path.abspath(src)), "WarFront_editor.exe")
open(dst, "wb").write(data)
print("written", dst)
