import contextlib
import io
import os
import tempfile
import unittest

import warfront
from decompress_inf import detect_format, text_to_binary


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = warfront.main(list(argv), prog='warfront.py')
    return code, out.getvalue(), err.getvalue()


class CommandLineTests(unittest.TestCase):
    def test_help_lists_every_command(self):
        code, out, _ = run('--help')
        self.assertEqual(code, 0)
        for name in warfront.COMMANDS:
            self.assertIn(name, out)

    def test_no_command_is_an_error(self):
        code, out, _ = run()
        self.assertEqual(code, 2)
        self.assertIn('commands:', out)

    def test_unknown_command(self):
        code, _, err = run('bogus')
        self.assertEqual(code, 2)
        self.assertIn("unknown command 'bogus'", err)

    def test_command_help_uses_combined_prog(self):
        for name in warfront.COMMANDS:
            with self.subTest(command=name), self.assertRaises(SystemExit) as exit_:
                run(name, '-h')
            self.assertEqual(exit_.exception.code, 0)

    def test_inf_converts_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, 'in.inf')
            target = os.path.join(tmp, 'out.inf')
            with open(source, 'wb') as f:
                f.write(text_to_binary('[A : cA]\r\n{\r\n\tV = 1\r\n}\r\n'))
            code, _, _ = run('inf', '-t', '-f', source, target)
            self.assertEqual(code, 0)
            with open(target, 'rb') as f:
                data = f.read()
            self.assertEqual(detect_format(data), 'text')
            self.assertIn(b'V = 1', data)

    def test_launch_needs_an_action(self):
        with self.assertRaises(SystemExit) as exit_:
            run('launch', 'WarFront.exe')
        self.assertEqual(exit_.exception.code, 2)

    def test_patch_demo_reports_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            bogus = os.path.join(tmp, 'WarFront.exe')
            with open(bogus, 'wb') as f:
                f.write(b'not an exe')
            code, _, err = run('patch-demo', bogus)
        self.assertEqual(code, 1)
        self.assertIn('Error:', err)


if __name__ == '__main__':
    unittest.main()
