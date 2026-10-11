"""
WarFront: Turning Point tools

One command line for every tool in this repository:

  warfront.py inf ...          convert INF files between binary and text (decompress_inf.py)
  warfront.py widescreen ...   build the widescreen interface patch (widescreen.py)
  warfront.py launch ...       start the game with the editor and/or Debug Mode unlocked (editor_unlock.py)
  warfront.py patch-demo ...   write an editor-mode copy of the SP demo exe (editor_unlock.py)

Run `warfront.py COMMAND -h` for a command's options.
"""

import importlib
import os
import sys

# command: (module, function, summary)
COMMANDS = {
    'inf': ('decompress_inf', 'main', 'convert INF files between binary and text'),
    'widescreen': ('widescreen', 'main', 'build the widescreen interface patch'),
    'launch': ('editor_unlock', 'main_launch', 'start the game with the editor and/or Debug Mode (Windows)'),
    'patch-demo': ('editor_unlock', 'main_patch_demo', 'write an editor-mode copy of the SP demo exe'),
}


def usage(prog):
    lines = [f'usage: {prog} COMMAND [options]', '', 'WarFront: Turning Point tools', '', 'commands:']
    lines += [f'  {name:<12} {summary}' for name, (_, _, summary) in COMMANDS.items()]
    lines += ['', f'Run "{prog} COMMAND -h" for a command\'s options.']
    return '\n'.join(lines)


def main(argv=None, prog=None):
    argv = sys.argv[1:] if argv is None else argv
    prog = prog or os.path.basename(sys.argv[0]) or 'warfront.py'
    if not argv or argv[0] in ('-h', '--help'):
        print(usage(prog))
        return 0 if argv else 2
    command, rest = argv[0], argv[1:]
    if command not in COMMANDS:
        print(usage(prog), file=sys.stderr)
        print(f'\n{prog}: unknown command {command!r}', file=sys.stderr)
        return 2
    module, function, _ = COMMANDS[command]
    run = getattr(importlib.import_module(module), function)
    return run(rest, prog=f'{prog} {command}') or 0


if __name__ == '__main__':
    sys.exit(main())
