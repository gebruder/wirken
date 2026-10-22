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
        self.assertEqual(module.summary(sections["1.7.2"][1]), "Bump wasmtime.")


if __name__ == "__main__":
    unittest.main()
