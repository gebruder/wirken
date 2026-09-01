#!/usr/bin/env python3
"""Report which *fields* an Anthropic export carries for one message.

Companion to ``anthropic-export-schema.py``. That one answers "what
shape is this archive"; this one answers "what does the archive hold
for this specific message, and does the importer read all of it".

    python3 scripts/anthropic-export-message-fields.py export.zip <message-uuid>

The question it exists for: a store held 15506 messages whose flattened
``text`` was empty and whose only content block was a ``text`` block
whose own text was also empty. Either the archive carries no text for
them, or it carries it under a key the importer does not parse. The
store cannot tell those apart, because it keeps the ``content`` array
verbatim and nothing else from the message object. Only the archive
can, and only field by field.

Safety model
------------
The default for every value is "do not print it". This prints key
names, JSON types and value *sizes*, and nothing else -- so the output
of a run against a real archive is safe to paste into a design
discussion, which is the same property the schema extractor holds and
for the same reason.

Message content reaches the output through no path. A string is
reported as its length, a list as its length, a dict as its sorted key
names, a number as its type. There is no flag to print values: a
switch that turns the gate off is a gate that gets turned off.

Dict keys are the one judgement call. They are schema, not content, in
every export shape seen so far -- ``{"uuid": ...}`` on an account, a
citation's field names -- and naming them is the whole point of the
tool. A key deep inside an unknown future block could in principle
carry content; the sizes beside it will not.

A block's ``type`` is the single value printed, because a report that
will not say whether a block is text or tool_use answers nothing. It
goes through ``safe_token`` first: short, and drawn from the character
set a discriminator uses. Anything else is reported as a length like
every other string, so an archive that puts content where this tool
expects an enum does not get a free pass.

Reading the output
------------------
Fields the importer parses are listed plainly. Fields it does not are
marked ``>>``. A ``>>`` field with a non-zero size is the finding: the
archive carries something the store never received.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile

# What `ExportMessage` in crates/gateway/src/imported_format.rs
# deserializes. Anything outside this set is dropped at import: serde
# ignores unknown fields, so a key added upstream costs its column
# silently. Keep in step with that struct.
PARSED_MESSAGE_KEYS = {
    "uuid",
    "sender",
    "text",
    "created_at",
    "updated_at",
    "attachments",
    "files",
    "content",
}

# What the conversation-detail projection renders from a content block.
# A block key outside this set is stored verbatim in `content_json` and
# shown to nobody.
RENDERED_BLOCK_KEYS = {
    "type",
    "text",
    "citations",
    "flags",
    "start_timestamp",
    "stop_timestamp",
}


# A discriminator is short and has no whitespace or punctuation beyond
# these. Anything else is content until proven otherwise.
SAFE_TOKEN_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
)
SAFE_TOKEN_MAX = 64


def safe_token(value):
    """`value` if it is shaped like an enum member, else None.

    The gate on the one field this tool prints by value. A `type` that
    is long, or carries characters a discriminator does not, is treated
    as content and reported as a size instead.
    """
    if not isinstance(value, str):
        return None
    if not value or len(value) > SAFE_TOKEN_MAX:
        return None
    if not set(value) <= SAFE_TOKEN_CHARS:
        return None
    return value


def describe(value) -> str:
    """A value's shape, never a value.

    Strings and lists report a length, dicts report their key names,
    numbers and booleans report their type. Nothing here returns
    anything derived from a string's characters.
    """
    if isinstance(value, str):
        return f"str len={len(value)}"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, list):
        return f"list len={len(value)}"
    if isinstance(value, dict):
        return f"dict keys={sorted(value)}"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return type(value).__name__
    return type(value).__name__


def load_conversations(archive: str):
    """The archive's conversations.json, parsed.

    Matches by suffix rather than exact name: exports have carried the
    file both at the root and under a dated directory.
    """
    with zipfile.ZipFile(archive) as z:
        names = [n for n in z.namelist() if n.endswith("conversations.json")]
        if not names:
            raise SystemExit(f"no conversations.json in {archive}")
        with z.open(names[0]) as f:
            return names[0], json.load(f)


def find_message(conversations, target: str):
    """The (conversation, message) carrying `target`, or (None, None)."""
    for conversation in conversations:
        if not isinstance(conversation, dict):
            continue
        messages = conversation.get("chat_messages")
        if not isinstance(messages, list):
            # A record whose chat_messages is not an array does not fit
            # the expected shape; the importer skips it by uuid and so
            # does this.
            continue
        for message in messages:
            if isinstance(message, dict) and message.get("uuid") == target:
                return conversation, message
    return None, None


def report(conversation, message, out) -> None:
    name = conversation.get("name")
    print(f"conversation name: {'<empty>' if not name else '<non-empty>'}", file=out)
    print(f"conversation keys: {sorted(conversation)}", file=out)
    print("", file=out)

    print("message fields (name -> shape, no values):", file=out)
    for key in sorted(message):
        mark = "   " if key in PARSED_MESSAGE_KEYS else ">> "
        print(f"  {mark}{key}: {describe(message[key])}", file=out)
    print("", file=out)

    blocks = message.get("content")
    print("content blocks:", file=out)
    if not isinstance(blocks, list) or not blocks:
        print("  (none)", file=out)
    else:
        for i, block in enumerate(blocks):
            if not isinstance(block, dict):
                print(f"  [{i}] {describe(block)}", file=out)
                continue
            keys = sorted(block)
            unrendered = [k for k in keys if k not in RENDERED_BLOCK_KEYS]
            token = safe_token(block.get("type"))
            shown = repr(token) if token is not None else describe(block.get("type"))
            line = f"  [{i}] type={shown} keys={keys}"
            if unrendered:
                line += f"  NOT-RENDERED={unrendered}"
            print(line, file=out)
            for key in keys:
                # `type` is already on the line above, by value or by
                # size; repeating its length says nothing.
                if key != "type" and isinstance(block[key], str):
                    print(f"       {key}: {describe(block[key])}", file=out)
    print("", file=out)
    print(">> marks a field the importer does not parse.", file=out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Report field names and sizes (never values) for one "
                    "message in an Anthropic data export.")
    ap.add_argument("archive", help="export .zip file")
    ap.add_argument("message_uuid", help="uuid of the message to report on")
    ap.add_argument("--out", help="write report here instead of stdout")
    args = ap.parse_args()

    member, conversations = load_conversations(args.archive)
    conversation, message = find_message(conversations, args.message_uuid)
    if message is None:
        print(f"message {args.message_uuid} not found in {member}", file=sys.stderr)
        return 1

    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        report(conversation, message, out)
    finally:
        if args.out:
            out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
