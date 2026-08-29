#!/usr/bin/env python3
"""Tests for the export schema extractor's content and identifier gate.

    python3 scripts/test_anthropic_export_schema.py

Fixture rule
------------
**Every JSON type appears, populated, carrying a hostile-shaped value.**

Two ways a fixture can look like coverage without being it, both of
which happened here:

*By nullity.* An earlier fixture set ``verified_phone_number`` to null.
The field was present and the suite passed, but a null never reaches
the value path, so the gate that should have suppressed phone numbers
was never run against one. A real archive put populated numbers through
it and they came out.

*By type.* The fixture that replaced it was populated but entirely
strings. Integers reach the report by a different route, as the bounds
of a numeric range, and that route did not consult the gate. Real
record ids came out that way, in the same digit shape the string gate
was already rejecting.

So the rule is both halves: populated, and every type. To claim a field
is covered, give it a value that should be suppressed, in the type the
archive actually uses, then assert the output does not contain it.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
import zipfile

_HERE = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "export_schema", _HERE / "anthropic-export-schema.py"
)
export_schema = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(export_schema)


# Values that must never appear in a report, each paired with why it is
# dangerous. Keys are deliberately a mix: some on the content denylist,
# some named nothing in particular, because the backstop must not
# depend on the key name.
HOSTILE = {
    "verified_phone_number": "+12025550143",   # denylisted key, plus prefix
    "contact_line": "+442071838750",           # phone under an unremarkable key
    "callback": "2025550143",                  # phone with no punctuation
    "owner_ref": "person@example.invalid",     # email under a non-email key
    "pan": "4111111111111111",                 # card-shaped digits
    "widget": "550e8400-e29b-41d4-a716-446655440000",  # uuid
    "endpoint": "https://internal.example.invalid/secret",  # url
    "day": "2026-01-02",                       # date
    "when": "2026-01-02T03:04:05Z",            # timestamp
    "full_name": "Hostile Name",               # denylisted key
    "email_address": "other@example.invalid",  # denylisted key
}

# Numbers do not travel the closed-set path. They surface as the bounds
# of a range, which are two real values, so they need their own fixture
# and their own assertions.
HOSTILE_NUMBERS = {
    "record_id": 4769238125,        # identifying integer, as a range bound
    "other_record_id": 34175926611,  # the other bound
    "ratio": 1234567.89,             # float: type only, never a range
}

# Numeric ranges that must SURVIVE, for the same reason the enums must:
# a report that suppressed every number would be safe and useless.
BENIGN_NUMBERS = {"page_size": 20, "retries": 3}

# Low-cardinality values that must SURVIVE. Without these the suite
# would pass just as well against a gate that suppressed everything,
# which would make the tool useless rather than safe.
EXPECTED_ENUMS = {
    "sender": ["assistant", "human"],
    "block_kind": ["text", "thinking"],
    "limit_code": ["24"],
    "resource_type": ["Doc", "Folder"],
}

CANARY_TEXT = "CANARYBODY"
CANARY_TITLE = "CANARYTITLE"
CANARY_FILENAME = "CANARYFILENAME.pdf"


def build_archive(path: pathlib.Path) -> None:
    """An archive where every field is populated and most are hostile."""
    rows = []
    for i in range(4):
        row = dict(HOSTILE)
        row["sender"] = EXPECTED_ENUMS["sender"][i % 2]
        row["block_kind"] = EXPECTED_ENUMS["block_kind"][i % 2]
        row["limit_code"] = "24"
        row["resource_type"] = EXPECTED_ENUMS["resource_type"][i % 2]
        row["text"] = f"{CANARY_TEXT} body {i}"
        row["name"] = f"{CANARY_TITLE}{i}"
        # Both bounds present so the range spans the identifying values.
        row["record_id"] = HOSTILE_NUMBERS["record_id"] if i % 2 else \
            HOSTILE_NUMBERS["other_record_id"]
        row["ratio"] = HOSTILE_NUMBERS["ratio"]
        row.update(BENIGN_NUMBERS)
        rows.append(row)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("conversations.json", json.dumps(rows))
        z.writestr(f"attachments/{CANARY_FILENAME}", b"%PDF-1.4 body")


def build_null_archive(path: pathlib.Path) -> None:
    """The fixture shape this suite exists to reject: fields set to null."""
    rows = [{"verified_phone_number": None, "sender": "human"} for _ in range(4)]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("conversations.json", json.dumps(rows))


def report_for(builder) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        archive = pathlib.Path(tmp) / "export.zip"
        out = pathlib.Path(tmp) / "report.txt"
        builder(archive)
        with open(out, "w", encoding="utf-8") as fh:
            walker = export_schema.report_archive(
                str(archive), export_schema.MAX_ENUM_DEFAULT, fh
            )
            export_schema.print_fields(walker, export_schema.MAX_ENUM_DEFAULT, fh)
        return out.read_text(encoding="utf-8")


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = report_for(build_archive)

    def test_no_hostile_value_reaches_the_report(self):
        for key, value in HOSTILE.items():
            with self.subTest(field=key):
                self.assertNotIn(value, self.report)

    def test_phone_digits_do_not_reach_the_report_in_any_form(self):
        # Belt and braces: the raw string could be absent while a
        # substring of it survived some future formatting change.
        for digits in ("2025550143", "442071838750", "4111111111111111"):
            with self.subTest(digits=digits):
                self.assertNotIn(digits, self.report)

    def test_message_and_title_content_do_not_reach_the_report(self):
        self.assertNotIn(CANARY_TEXT, self.report)
        self.assertNotIn(CANARY_TITLE, self.report)

    def test_attachment_filename_is_redacted_in_the_inventory(self):
        self.assertNotIn(CANARY_FILENAME, self.report)
        self.assertIn("<redacted-", self.report)

    def test_legitimate_enums_survive(self):
        # A gate that suppressed everything would pass every test above.
        emitted = [l for l in self.report.split("\n") if "values=[" in l]
        for field, values in EXPECTED_ENUMS.items():
            with self.subTest(field=field):
                wanted = "values=[" + "|".join(sorted(values)) + "]"
                self.assertTrue(
                    any(wanted in line for line in emitted),
                    f"{field} should still emit {wanted}",
                )

    def test_identifying_numbers_are_banded_not_printed(self):
        # The bug this covers: min/max are two real values and reached
        # the report without passing the gate the strings passed.
        for value in (4769238125, 34175926611):
            with self.subTest(value=value):
                self.assertNotIn(str(value), self.report)
        self.assertIn("-digit..", self.report)

    def test_float_values_never_reach_the_report(self):
        self.assertNotIn("1234567.89", self.report)
        self.assertNotIn("1234567", self.report)

    def test_benign_numeric_ranges_survive(self):
        # A report that banded every number would pass the test above.
        self.assertIn("num=20..20", self.report)
        self.assertIn("num=3..3", self.report)

    def test_report_is_deterministic(self):
        self.assertEqual(self.report, report_for(build_archive))


class IdentifyingValueTests(unittest.TestCase):
    def test_digits_are_counted_across_punctuation(self):
        # The bug that motivated this: a leading '+' defeated a
        # ^-?\d+$ shaped check, so the number was treated as an enum.
        for value in ("+12025550143", "1-202-555-0143", "(202) 555 0143",
                      "+44 20 7183 8750", "2025550143"):
            with self.subTest(value=value):
                self.assertTrue(export_schema.looks_identifying(value))

    def test_short_codes_and_words_are_not_identifying(self):
        for value in ("24", "3000", "human", "web_search", "Doc", "en"):
            with self.subTest(value=value):
                self.assertFalse(export_schema.looks_identifying(value))


class SharedThresholdTests(unittest.TestCase):
    """The string gate and the numeric range must not drift apart."""

    def test_both_paths_use_one_threshold(self):
        n = "9" * export_schema.IDENTIFYING_DIGITS
        self.assertTrue(export_schema.looks_identifying(n))
        self.assertIn("-digit..", export_schema.num_range_label(int(n), int(n)))
        m = "9" * (export_schema.IDENTIFYING_DIGITS - 1)
        self.assertFalse(export_schema.looks_identifying(m))
        self.assertNotIn("-digit..", export_schema.num_range_label(int(m), int(m)))


class NullFixtureTests(unittest.TestCase):
    """A null field is an unexercised path, not a covered one."""

    def test_null_field_produces_no_evidence_about_the_gate(self):
        report = report_for(build_null_archive)
        # The field is visible in the report as null-typed...
        self.assertIn("verified_phone_number", report)
        self.assertIn("types=null:", report)
        # ...and carries no values= line, which is exactly what a
        # correctly suppressed populated field also looks like. The two
        # cases are indistinguishable in the output, which is why a
        # null fixture cannot demonstrate suppression.
        phone_lines = [
            l for l in report.split("\n")
            if "values=[" in l and "verified_phone_number" in l
        ]
        self.assertEqual(phone_lines, [])

    def test_populated_fixture_is_what_demonstrates_suppression(self):
        # The same field, populated, is the only version that shows the
        # gate did anything. This test is the reason the rule exists.
        populated = report_for(build_archive)
        self.assertNotIn(HOSTILE["verified_phone_number"], populated)
        self.assertTrue(
            export_schema.looks_identifying(HOSTILE["verified_phone_number"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
