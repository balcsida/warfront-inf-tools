# War Front: Turning Point: unlocking the built-in editor and debug tools

Reverse-engineering notes for *War Front: Turning Point* (Digital Reality / 10TACLE, 2007),
covering the **Singleplayer Demo 1.01** and the **Hungarian retail** release.

**TL;DR**

* The gameplay debug hotkeys (god mode, extra money, fog of war off, kill all, free camera,
  teleport…) were **compiled out** of both builds. They can't be enabled.
* The full in-house **level editor** (window title *CoE*) is still in `WarFront.exe`, locked
  behind one hard-coded string. Changing one 4-byte pointer unlocks it. It has been tested and
  opens in both the demo and the retail build.
* The editor has a render-debug panel (**DEBUG PROPS**) and a **Tools → Debug Mode** switch,
  which relaxes tech/production availability checks in single-player.

---

## 1. Debug hotkeys are dead

`WarFront.exe` builds a static command table of `GameArea_*` input commands. Each entry has a
name and a handler; the `U`/`D` suffix means key up/down. The `D_` (debug) commands are still
present:

```
D_DEBUGMODE  D_EMPERORMODE  D_NODAMAGEMODE  D_GODMODE  D_DEBUG1 … D_DEBUG9
D_FOWONOFF   D_FREECAMERA   D_KILLALL       D_DAMAGEALL  D_TELEPORT  D_LEVELUP
D_WIND       D_LOST         D_EXTRAMONEY    D_RELOADLEVEL  D_ATMOSPHERE
D_SAVERESOURCESDUMP  D_SHOWFPSCOUNTER  D_CAMERAREPLAYSTARTSTOP  D_HDDWRITESTARTSTOP
D_PROPERTY_WINDOW  D_OPEN_WORLD  D_OPEN_GAME
```

In both builds every one of these points either to a shared empty `ret 4` stub (demo
`0x7BC2E0`, retail `0x76B7F0`) or to an empty SEH-framed function (`D_DEBUG2`,
`D_PROPERTY_WINDOW`). The only one with real code is `D_SAVERESOURCESDUMP`, which asks the
resource manager to write a dump. `START_GAME_RECORD`, `START_GAME_REPLAY`,
`QUICKSAVE_REPLAY`, `NEXTCOREUNIT`/`PREVCOREUNIT` and `FOLLOWUNITTOGGLE` are stubbed as well.

Binding these in `hotkeys.txt` therefore does nothing useful.

Settings are no better. `stub\system\startappmode` in `Local Settings.setting` is **ignored**
(see §2). `debug\drawsectors` registers a draw routine, but that routine only calls the empty
stub.

## 2. The editor (CoE)

### Why it's hidden

In the stub initialiser (`Settings.setting` / `Local Settings.setting` are loaded here) the app
mode is assigned from a constant instead of from the setting:

```c
appModeName = "game";                      // push offset "game"; call CString::operator=
isGame   = strcmp(appModeName, "game")   == 0;   // [this+0x42]
isEditor = strcmp(appModeName, "editor") == 0;   // [this+0x43]
```

`isEditor` is returned by the app object's virtual `+0xCC` (`mov al,[ecx+0x43]; ret`). The
start-up routine that registers the app modes only registers the **editor** and **GUI editor**
modes when that returns true. All the editor code, dialogs, toolbars and menus are compiled in.

### The patch

Replace the pushed string pointer `"game"` with the existing `"editor"` string:

| Build | VA of `push "game"` | Original bytes | New bytes | `"editor"` VA |
|---|---|---|---|---|
| SP demo 1.01 | `0x7AA363` (file offset `0x3AA363`) | `68 4C ED BE 00` | `68 C4 CC C1 00` | `0xC1CCC4` |
| Retail (HUN) | `0x7AE0A3` | `68 E4 1D BF 00` | `68 54 FD C1 00` | `0xC1FD54` |

* **Demo:** the exe isn't encrypted, so a static patch works:
  `python patch_spdemo.py "...\Run\WarFront.exe"` writes `WarFront_editor.exe` next to it.
* **Retail:** `WarFront.exe` is encrypted on disk (a protector stub in `.init` plus `hc.dll`
  decrypts it at start-up), so a file patch isn't possible. `wf_launch.py` starts the game,
  polls the patch site until the decrypted bytes appear (≈50–350 ms), and writes the new
  pointer before the start-up code reaches it:
  `python wf_launch.py "...\WarFront.exe" --editor`.
  The launcher recognises the build by the original bytes and refuses unknown builds.

The image base is fixed at `0x400000` (no ASLR). The editor opens as a normal window titled
**"CoE - <level path>"** and reopens the last level from its recent-files list.

### What's in it

Toolbar (tooltips from the string table): Place / Landscape / Select tools, show/hide
entities, shadows, **water**, **HP bars**, landscape LOD, physics primitives, texture layers,
landscape LOD texture generation, **DEBUG PROPS**, camera N/S/E/W/Top, grid & snap,
randomised placement, wiring, FPS…

Menus (from the `MENU` resource):

* **File:** New, Open, Save, Save as, Save Trigger, Save global params, Revert, Save/Load
  entities, Save minimap picture, Save shadowmap picture
* **Edit:** Undo, Redo, Collapse/Explode objects
* **View:** Entities, Entity Bases, World, **Game**, Skills, Schema editor, Game content,
  Terrain types, Camera keyframer, Alliance table, **Settings**, Damage multiplier table, Hit
  effect table, **Log window**, Edit info, Query table, Speech actors, **Entity stats**, Message
  logger, Resource table, Component table, **Trigger Editor**, **GUI Editor**
* **Tools:** **Debug Mode**, Lock scripted, Show usage stat, Rescale level, camera zoom-limit
  switch (Alt+Z), terrain brush on selection, Generate lightmap, grass and road/fence
  generators, entity-base tools, wiring, carve pits, mount/unmount/dig in/dig out, heightmap
  export (raw / DirectX .X) and import, **Recording / Replay gameplay**, permanent effects
  on/off, save generated models
* **Multiplayer:** Create server, Join to a server
* **Modes:** filled at run time with the registered app modes (game, editor, GUI editor)

### DEBUG PROPS (toolbar ID `0x50F3`, "Debugging Properties")

Opens the *Debug Features* property window (`cRenderDebugControl`). It is purely a
**render** debug tool:

| Group | Properties |
|---|---|
| Visibility | Entities, Brushes, Terrain, Water, PostProcessEffects, ShadowMap, CloudShadow, Occluders, UpdateOccluders |
| DebugTools | Profiler (its global `0xF7BC20` in the demo is never read, so it does nothing) |
| VisualQuality | LowQualityLighting, ShadowmapSize, TexSamplingQuality (0–16), MaxMipLevel (≥1) |
| PostProcessParameters | RadialBlur, MotionBlur, MotionBlur_AAKernelSize / _Bluring / _MovingSpeed / _ShutterSpeed |

### Tools → Debug Mode (command ID `0x8061`)

This toggles a single byte on the game app object:

```
mov ecx,[gameApp]; mov esi,[ecx]; call [esi+0x94]   ; get  -> mov al,[ecx+0x10]
... sete al; push eax; call [esi+0x90]              ; set  -> mov [ecx+0x10],al
```

| Build | `gameApp` pointer | Flag |
|---|---|---|
| SP demo 1.01 | `[0xE86E90]` | `[[0xE86E90]+0x10]` |
| Retail (HUN) | `[0xE891B8]` | `[[0xE891B8]+0x10]` |

About 29 game-logic sites read it. The ones examined bypass tech / production / research
availability checks for the **local player in non-multiplayer games**. For example, an item
counts as available when debug mode is on, the game isn't multiplayer, and the item belongs to
the local player. The same flag can be set without the editor, e.g. by writing `1` there with
Cheat Engine or x32dbg (`wf_launch.py --debug-mode` does this but is untested).

## 3. Status

| Item | Status |
|---|---|
| Editor opens (demo, static patch) | ✅ tested |
| Editor opens (retail, in-memory patch) | ✅ tested; auto-loads the last level |
| D_* debug hotkeys | ❌ compiled out in both builds |
| DEBUG PROPS panel contents | from static analysis |
| Debug Mode effect in gameplay | from static analysis, not play-tested |
| `wf_launch.py --debug-mode` | untested |
| Demo editor assets | the demo lacks `CommonAssets\Editor\…` (atmosphere editor defaults), so some panels may warn |

## Usage

Requires Windows and Python 3; no extra packages. Tested with 64-bit Python 3.14 against the
32-bit game.

```
# Retail (or demo): start the editor via an in-memory patch
python wf_launch.py "C:\Games\War Front\WarFront.exe" --editor

# SP demo only: write a patched copy, WarFront_editor.exe
python patch_spdemo.py "C:\Games\War Front Demo\Run\WarFront.exe"
```

## Files

* `wf_launch.py`: in-memory launcher (`--editor`, `--debug-mode`), works with both builds
* `patch_spdemo.py`: static patch for the SP demo 1.01 exe

*Analysis done with Ghidra plus small Python helpers (PE parsing, command-table extraction,
resource/menu dump, process memory dump). No game files are included here.*
