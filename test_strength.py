"""Tests for strength.py and the command line tool.

Run them with:  python3 -m unittest discover -s tests
"""

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import strength


class CheckTests(unittest.TestCase):
    def test_common_password(self):
        result = strength.check("password")
        self.assertLessEqual(result["score"], 15)
        self.assertEqual(result["label"], "very weak")

    def test_common_password_with_substitutions(self):
        result = strength.check("P@ssw0rd")
        self.assertIn("common", result["patterns"])
        self.assertLessEqual(result["score"], 15)

    def test_long_random_password(self):
        result = strength.check("vT7#qL2!zR9@wK4$")
        self.assertGreaterEqual(result["score"], 80)
        self.assertEqual(result["label"], "very strong")

    def test_short_password_is_capped(self):
        self.assertLessEqual(strength.check("Ab1!")["score"], 35)

    def test_empty_password(self):
        result = strength.check("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["crack_time"], "instantly")

    def test_personal_info(self):
        result = strength.check("abdelrahman27", ["abdelrahman"])
        self.assertIn("personal", result["patterns"])

    def test_keyboard_sequence(self):
        result = strength.check("qwerty123")
        self.assertIn("sequence", result["patterns"])

    def test_repeated_block(self):
        result = strength.check("abcabcabc")
        self.assertIn("repeat", result["patterns"])

    def test_year_is_flagged(self):
        result = strength.check("mohamed1995")
        self.assertIn("1995", result["patterns"]["date"])

    def test_longer_is_stronger(self):
        short = strength.check("k7#pLq2!")
        long = strength.check("k7#pLq2!vR8@wZ4$")
        self.assertGreater(long["score"], short["score"])


class GenerateTests(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(strength.generate(24)), 24)

    def test_uses_every_character_type(self):
        password = strength.generate(12)
        kinds = strength.count_classes(password)
        self.assertEqual(len(kinds), 4)

    def test_readable_skips_confusing_characters(self):
        password = strength.generate(30, readable=True)
        for char in "0O1lI|":
            self.assertNotIn(char, password)

    def test_no_symbols(self):
        password = strength.generate(16, symbols=False)
        self.assertTrue(password.isalnum())

    def test_too_short(self):
        with self.assertRaises(ValueError):
            strength.generate(4)


class TimeTests(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(strength.readable_time(0), "instantly")

    def test_hours(self):
        self.assertEqual(strength.readable_time(5 * 3600), "5 hours")

    def test_huge(self):
        self.assertIn("universe", strength.readable_time(10 ** 40))


class CommandLineTests(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "password_checker.py")] + list(args),
            capture_output=True, text=True, cwd=ROOT)

    def test_json_output(self):
        done = self.run_tool("-p", "test1234", "--json")
        self.assertEqual(done.returncode, 0)
        data = json.loads(done.stdout)
        self.assertIn("score", data)
        self.assertNotIn("test1234", done.stdout)

    def test_fail_under(self):
        done = self.run_tool("-p", "123456", "--fail-under", "60")
        self.assertEqual(done.returncode, 1)

    def test_generate_output(self):
        done = self.run_tool("--generate", "--length", "18")
        self.assertEqual(done.returncode, 0)
        self.assertIn("score", done.stdout)


if __name__ == "__main__":
    unittest.main()
