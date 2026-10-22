#!/usr/bin/env python3
"""Tests for check-security-heading.py's CHANGELOG reading."""

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "check-security-heading.py"
spec = importlib.util.spec_from_loader("check_security_heading", loader=None)
module = importlib.util.module_from_spec(spec)
module.__file__ = str(SCRIPT)
exec(compile(SCRIPT.read_text(), str(SCRIPT), "exec"), module.__dict__)

BEFORE_BUMP = """# Changelog

## [Unreleased]

### Added

- a thing.

## [2.4.0] - 2026-10-21

### Security

- an old fix.
"""

AFTER_BUMP = """# Changelog

## [Unreleased]

## [2.5.0] - 2026-10-23

### Fixed

- a thing.

## [2.4.0] - 2026-10-21

### Security

- an old fix.
"""


class ReleaseSection(unittest.TestCase):
    def test_unreleased_is_the_release_section_before_the_bump(self):
        name, body = module.release_section(BEFORE_BUMP)
        self.assertEqual(name, "Unreleased")
        self.assertIn("- a thing.", body)
        self.assertFalse(module.has_security(body))

    def test_the_new_version_is_the_release_section_after_the_bump(self):
        name, body = module.release_section(AFTER_BUMP)
        self.assertEqual(name, "2.5.0")
        self.assertFalse(module.has_security(body), "the previous release's heading does not count")

    def test_a_security_heading_is_an_exact_line(self):
        self.assertTrue(module.has_security("### Security\n\n- x"))
        self.assertTrue(module.has_security("  ### Security  "))
        self.assertFalse(module.has_security("### Security fixes"))
        self.assertFalse(module.has_security("Security"))

    def test_an_empty_changelog_has_no_release_section(self):
        self.assertEqual(module.release_section("# Changelog\n\n## [Unreleased]\n"), (None, ""))


if __name__ == "__main__":
    unittest.main()
