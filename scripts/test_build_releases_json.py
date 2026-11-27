#!/usr/bin/env python3
"""Tests for build-releases-json.py's time and CHANGELOG handling."""

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "build-releases-json.py"
spec = importlib.util.spec_from_loader("build_releases_json", loader=None)
module = importlib.util.module_from_spec(spec)
module.__file__ = str(SCRIPT)
exec(compile(SCRIPT.read_text(), str(SCRIPT), "exec"), module.__dict__)


class TagTime(unittest.TestCase):
    def test_a_tag_time_east_of_utc_can_fall_on_the_previous_utc_day(self):
        self.assertEqual(module.to_utc("2026-10-23T00:43:20+02:00"), "2026-10-22T22:43:20Z")

    def test_utc_and_western_offsets(self):
        self.assertEqual(module.to_utc("2026-10-21T19:02:36Z"), "2026-10-21T19:02:36Z")
        self.assertEqual(module.to_utc("2026-10-21T20:30:00-05:00"), "2026-10-22T01:30:00Z")

    def test_a_time_without_an_offset_is_refused(self):
        with self.assertRaises(ValueError):
            module.to_utc("2026-10-23T00:43:20")

    def test_a_missing_tag_is_none(self):
        self.assertIsNone(module.tag_time("0.0.0-no-such-tag"))


class Changelog(unittest.TestCase):
    TEXT = "# Changelog\n\n## [Unreleased]\n\n## [1.7.2] - 2026-05-25\n\n### Sandbox security fix\n\n- Bump wasmtime.\n\n### Security\n\n- wasmtime closes RUSTSEC-2026-0149.\n\n## [1.7.1] - 2026-05-20\n\n### Fixed\n\n- A thing.\n"

    def test_only_the_exact_security_heading_counts(self):
        sections = module.changelog_sections(self.TEXT)
        self.assertTrue(module.has_security(sections["1.7.2"][1]))
        self.assertFalse(module.has_security(sections["1.7.1"][1]))

    def test_the_summary_is_the_first_bullets_first_sentence(self):
        sections = module.changelog_sections(self.TEXT)
        self.assertEqual(module.summary(sections["1.7.1"][1]), "A thing.")

    def test_a_security_release_is_summarised_by_its_security_bullets(self):
        sections = module.changelog_sections(self.TEXT)
        self.assertEqual(module.summary(sections["1.7.2"][1]), "wasmtime closes RUSTSEC-2026-0149.")
        body = (
            "### Operator notes\n\n- One gateway serves a directory. More.\n\n"
            "### Security\n\n- A cannot send B. Detail (`t`).\n- `c` refuses\n  inside d.\n\n"
            "### Added\n\n- A feature.\n"
        )
        self.assertEqual(module.summary(body), "A cannot send B. c refuses inside d.")

    def test_a_sentence_that_fits_is_kept_whole(self):
        sentence = "word " * 39 + "end."
        self.assertEqual(len(sentence), module.MAX_SUMMARY - 1)
        self.assertEqual(module.fit(sentence), sentence)

    def test_a_long_sentence_is_cut_between_words(self):
        sentence = " ".join(["abcdefgh"] * 40) + "."
        cut = module.fit(sentence)
        self.assertLessEqual(len(cut), module.MAX_SUMMARY)
        self.assertTrue(cut.endswith("abcdefgh..."), cut)
        self.assertTrue(sentence.startswith(cut[:-3] + " "))

    def test_a_long_sentence_is_cut_after_a_clause_where_one_is_near(self):
        sentence = "a" * 120 + " bb, " + "word " * 30 + "end."
        self.assertEqual(module.fit(sentence), "a" * 120 + " bb...")

    def test_a_comma_inside_parentheses_is_not_a_clause_end(self):
        sentence = "a" * 120 + " (one, two, three, " + "word " * 30 + "four) end."
        cut = module.fit(sentence)
        self.assertLessEqual(len(cut), module.MAX_SUMMARY)
        self.assertTrue(cut.endswith("word..."), cut)

    def test_security_sentences_past_the_limit_are_kept_whole_or_left_out(self):
        first, second, third = "a" * 90 + ".", "b" * 90 + ".", "c" * 40 + "."
        body = f"### Security\n\n- {first} More.\n- {second}\n- {third}\n"
        self.assertEqual(module.summary(body), f"{first} {second[:-1]}...")

    def test_a_first_security_sentence_past_the_limit_is_cut_between_words(self):
        body = "### Security\n\n- " + " ".join(["abcdefgh"] * 40) + ".\n- Short.\n"
        cut = module.summary(body)
        self.assertLessEqual(len(cut), module.MAX_SUMMARY)
        self.assertTrue(cut.endswith("abcdefgh..."), cut)

    def test_one_word_longer_than_the_limit_is_cut_to_fit(self):
        cut = module.fit("x" * 300)
        self.assertEqual(cut, "x" * (module.MAX_SUMMARY - 3) + "...")


class SecurityIsStated(unittest.TestCase):
    """The release being cut says whether it carries security fixes: by
    its heading, or by the flag. A missing heading alone builds nothing."""

    def build(self, changelog, *flags):
        import subprocess, sys, tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / "CHANGELOG.md").write_text(changelog)
            (tmp / "checksums.sha256").write_text("0" * 64 + "  wirken-x86_64-unknown-linux-musl\n")
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--current", self.TAG, "--offline",
                 "--checksums", str(tmp / "checksums.sha256"),
                 "--changelog", str(tmp / "CHANGELOG.md"), *flags],
                capture_output=True, text=True,
            )

    # A tag this repository has, for the entry's issued_at.
    TAG = "v3.5.0"
    PLAIN = "## [3.5.0] - 2026-11-22\n\n### Operator notes\n\n- A note.\n"
    FIXES = PLAIN + "\n### Security\n\n- A fix.\n"

    def setUp(self):
        if module.tag_time("3.5.0") is None:
            self.skipTest("this checkout has no v3.5.0 tag")

    def test_no_heading_and_no_flag_is_refused(self):
        out = self.build(self.PLAIN)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("--no-security-fixes", out.stderr)

    def test_no_heading_with_the_flag_is_a_release_without_fixes(self):
        out = self.build(self.PLAIN, "--no-security-fixes")
        self.assertEqual(out.returncode, 0, out.stderr)
        entry = __import__("json").loads(out.stdout)["releases"][0]
        self.assertEqual((entry["security"], entry["summary"]), (False, "A note."))

    def test_a_heading_is_a_release_with_fixes(self):
        out = self.build(self.FIXES)
        self.assertEqual(out.returncode, 0, out.stderr)
        entry = __import__("json").loads(out.stdout)["releases"][0]
        self.assertEqual((entry["security"], entry["summary"]), (True, "A fix."))

    def test_the_flag_against_a_heading_is_refused(self):
        self.assertNotEqual(self.build(self.FIXES, "--no-security-fixes").returncode, 0)


if __name__ == "__main__":
    unittest.main()
