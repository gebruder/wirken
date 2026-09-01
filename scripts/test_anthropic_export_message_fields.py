#!/usr/bin/env python3
"""Tests for the message-field reporter's content gate.

    python3 scripts/test_anthropic_export_message_fields.py

Fixture rule
------------
Inherited from ``test_anthropic_export_schema.py``, for the same
reason: **every JSON type appears, populated, carrying a
hostile-shaped value.**

The gate here is simpler than the extractor's -- this tool prints
sizes, not values, so there is no enum path and no identifier
heuristic to get wrong -- but it fails the same way if a fixture is
thin. A field left null never reaches the value path, so a report that
does not leak it demonstrates nothing. A fixture that is all strings
misses the dict path, which is the one place key names are printed and
therefore the one place a value could ride out as a key.

So: populated, and every type. To claim the gate holds for a shape,
put a value that must never appear into the fixture in that shape,
then assert the output does not contain it.
"""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
import zipfile

_HERE = pathlib.Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "export_message_fields", _HERE / "anthropic-export-message-fields.py"
)
message_fields = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(message_fields)


TARGET = "7a7a7a7a-7a7a-4a7a-8a7a-7a7a7a7a7a7a"

# Values that must never appear in a report. One per JSON type that can
# carry content, each under a key the importer does not parse, because
# an unparsed key is exactly the case this tool exists to surface and
# the case where a naive implementation would print the value to show
# what was missed.
HOSTILE = {
    "secret_string": "the transfer clears on Tuesday",
    "secret_list": ["a message body", "another one"],
    "secret_dict": {"note": "an inner message body"},
}
# Numbers reach the output by a different route than strings -- the
# extractor learned this the hard way -- so they get their own fixture
# entries rather than being assumed covered.
HOSTILE_NUMBERS = {
    "secret_int": 20255550143,
    "secret_float": 1234.5678,
}


def build_archive(path: pathlib.Path) -> None:
    """One conversation, one message, carrying every type populated."""
    message = {
        "uuid": TARGET,
        "sender": "human",
        "text": "",
        "created_at": "2026-07-02T03:04:05.000000Z",
        "updated_at": "2026-07-02T03:04:05.000000Z",
        "attachments": [],
        "files": [],
        "content": [
            {
                "type": "text",
                "text": "",
                "citations": [],
                "flags": None,
            }
        ],
        "secret_bool": True,
        "secret_null": None,
    }
    message.update(HOSTILE)
    message.update(HOSTILE_NUMBERS)

    conversations = [
        # A record the importer skips: chat_messages is not an array.
        # The reporter must walk past it rather than raising.
        {"uuid": "bad-1", "name": "", "chat_messages": "not an array"},
        # A record whose messages list holds a non-object.
        {"uuid": "bad-2", "name": "", "chat_messages": ["not an object"]},
        {
            "uuid": "c-1",
            "name": "",
            "summary": "",
            "chat_messages": [message],
        },
    ]
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("conversations.json", json.dumps(conversations))


def report_for(builder, target: str = TARGET) -> str:
    with tempfile.TemporaryDirectory() as d:
        archive = pathlib.Path(d) / "export.zip"
        builder(archive)
        _member, conversations = message_fields.load_conversations(str(archive))
        conversation, message = message_fields.find_message(conversations, target)
        assert message is not None, f"fixture must contain {target}"
        out = io.StringIO()
        message_fields.report(conversation, message, out)
        return out.getvalue()


class ContentGate(unittest.TestCase):
    def test_no_hostile_value_reaches_the_report(self):
        report = report_for(build_archive)
        for key, value in HOSTILE.items():
            with self.subTest(key=key):
                for text in _strings_in(value):
                    self.assertNotIn(
                        text,
                        report,
                        f"{key} put a value in the report; this tool prints sizes",
                    )

    def test_no_hostile_number_reaches_the_report(self):
        # Numbers are the route that defeated the extractor's first
        # gate: they were reported as range bounds, which did not
        # consult it. Here they must be reported as a type name only.
        report = report_for(build_archive)
        for key, value in HOSTILE_NUMBERS.items():
            with self.subTest(key=key):
                self.assertNotIn(str(value), report, f"{key} leaked its value")
        self.assertIn("secret_int: int", report)
        self.assertIn("secret_float: float", report)

    def test_every_field_is_reported_even_when_its_value_is_not(self):
        # Suppression is only useful if the field is still visible: the
        # whole point is telling the operator a field exists that the
        # importer drops.
        report = report_for(build_archive)
        for key in list(HOSTILE) + list(HOSTILE_NUMBERS) + ["secret_bool", "secret_null"]:
            self.assertIn(key, report)

    def test_sizes_are_reported_rather_than_contents(self):
        report = report_for(build_archive)
        self.assertIn(f"secret_string: str len={len(HOSTILE['secret_string'])}", report)
        self.assertIn(f"secret_list: list len={len(HOSTILE['secret_list'])}", report)
        # A dict reports its keys. Keys are schema; the values under
        # them are not printed.
        self.assertIn("secret_dict: dict keys=['note']", report)
        self.assertNotIn("an inner message body", report)


class UnparsedFieldMarking(unittest.TestCase):
    def test_fields_the_importer_drops_are_marked(self):
        report = report_for(build_archive)
        for key in list(HOSTILE) + list(HOSTILE_NUMBERS):
            self.assertIn(f">> {key}:", report, f"{key} must be marked unparsed")

    def test_fields_the_importer_reads_are_not_marked(self):
        report = report_for(build_archive)
        for key in ["uuid", "sender", "text", "attachments", "files", "content"]:
            self.assertNotIn(f">> {key}:", report, f"{key} is parsed and must not be marked")

    def test_the_marked_set_tracks_the_importer(self):
        # The marking is only true while this set matches ExportMessage
        # in crates/gateway/src/imported_format.rs. Pinned so a field
        # added there without updating this fails here rather than
        # producing a report that quietly marks a parsed field.
        self.assertEqual(
            message_fields.PARSED_MESSAGE_KEYS,
            {"uuid", "sender", "text", "created_at", "updated_at",
             "attachments", "files", "content"},
        )


class TokenGate(unittest.TestCase):
    def test_a_block_type_that_looks_like_content_is_not_printed(self):
        def builder(path: pathlib.Path) -> None:
            build_archive(path)
            with zipfile.ZipFile(path) as z:
                conversations = json.loads(z.read("conversations.json"))
            conversations[-1]["chat_messages"][0]["content"] = [
                {"type": "a whole sentence that is plainly not a discriminator"}
            ]
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("conversations.json", json.dumps(conversations))

        report = report_for(builder)
        self.assertNotIn("a whole sentence", report)
        self.assertIn("type=str len=", report)

    def test_a_real_discriminator_is_printed(self):
        # The gate has to let the useful case through, or the report
        # cannot say whether a block is text or tool_use.
        report = report_for(build_archive)
        self.assertIn("type='text'", report)

    def test_safe_token_rejects_what_it_should(self):
        self.assertEqual(message_fields.safe_token("tool_use"), "tool_use")
        self.assertEqual(message_fields.safe_token("text"), "text")
        self.assertIsNone(message_fields.safe_token("has a space"))
        self.assertIsNone(message_fields.safe_token("x" * 65))
        self.assertIsNone(message_fields.safe_token(""))
        self.assertIsNone(message_fields.safe_token(None))
        self.assertIsNone(message_fields.safe_token(42))


class MalformedRecords(unittest.TestCase):
    def test_records_the_importer_skips_do_not_stop_the_walk(self):
        # The corpus carries a conversation whose chat_messages is a
        # string and one whose message list holds a non-object. The
        # importer skips both; this must walk past them to reach the
        # message it was asked for, not raise on the way.
        report = report_for(build_archive)
        self.assertIn("message fields", report)

    def test_a_missing_message_is_reported_as_absent(self):
        with tempfile.TemporaryDirectory() as d:
            archive = pathlib.Path(d) / "export.zip"
            build_archive(archive)
            _member, conversations = message_fields.load_conversations(str(archive))
            conversation, message = message_fields.find_message(conversations, "no-such-uuid")
            self.assertIsNone(conversation)
            self.assertIsNone(message)


def _strings_in(value):
    """Every string inside a nested value, so a leak cannot hide in a list."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings_in(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings_in(item)


if __name__ == "__main__":
    unittest.main(verbosity=2)
