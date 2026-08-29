#!/usr/bin/env python3
"""Extract the *structure* of an Anthropic (claude.ai) data-export archive.

Run locally against a real export zip. Emits key paths, JSON types,
nullability, value shapes, and closed-set enum values. It does not emit
conversation text, titles, attachment bodies, or any other free-form
content, so the output is safe to paste into a design discussion.

    python3 scripts/anthropic-export-schema.py path/to/export.zip

Two archives can be passed at once; each is reported separately and a
merged view is printed last, so a field present in only one archive is
visible as such.

    python3 scripts/anthropic-export-schema.py a.zip b.zip

Safety model
------------
The default for every value is "do not print it". A value reaches the
output only when all of these hold:

* its key is not on CONTENT_KEYS (text, title, name, ... ),
* the field's distinct values across the whole archive number no more
  than --max-enum,
* every distinct value matches ENUM_VALUE_RE (short, no whitespace),
* no distinct value satisfies looks_identifying().

Numbers never reach that gate, because they are not collected as
candidate values. Their minimum and maximum are still two real values,
so the range goes through the same digit test and is replaced by a
digit-width band when either bound could identify. Floats report their
type only and carry no range.

The key denylist is the weaker of the two content controls and is not
relied on alone. looks_identifying() is the backstop and applies to
every candidate value whatever its key: it counts digits across the
whole string rather than matching a numeric shape, so a punctuated or
country-prefixed number is caught the same as a bare one.

Everything else is reported as type, presence, nullability, and a shape
classification derived from the value, never the value itself.

Determinism
-----------
All maps are emitted in sorted order and all counts are exact, so two
runs over the same archive produce byte-identical output.

Stdlib only. Python 3.9+.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict

# Keys whose values are content by definition. Never emitted, whatever
# their cardinality. Matched case-insensitively against the final path
# segment.
CONTENT_KEYS = {
    "text",
    "title",
    "name",
    "summary",
    "content",
    "body",
    "prompt",
    "message",
    "input",
    "output",
    "thinking",
    "display_content",
    "full_name",
    "email_address",
    "email",
    "description",
    "instructions",
    "file_name",
    "filename",
    "citation",
    "citations",
    "query",
    "answer",
    "url",
    "phone",
    "phone_number",
    "verified_phone_number",
    "address",
    "given_name",
    "family_name",
    "display_name",
    "username",
    "handle",
}

# A value may be emitted only if it matches this: short, no
# whitespace, no punctuation that could carry prose.
ENUM_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,48}$")

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")
DIGITS_RE = re.compile(r"^-?\d+$")

# Archive entry names printed verbatim. Anything else is redacted to
# directory + content hash + extension, since export archives carry
# attachment files under operator-supplied names.
SAFE_NAME_RE = re.compile(r"^[a-z0-9_-]+\.(json|jsonl|md|txt|csv)$")

MAX_ENUM_DEFAULT = 24

# A value carrying this many digits could identify a person or a record.
# Shared by the string gate and the numeric range so the two cannot
# disagree; they did once, and a phone number and a set of record ids
# went out through the half that was not guarded.
IDENTIFYING_DIGITS = 7


def digit_count(value) -> int:
    """Digits anywhere in the value's text form, punctuation ignored."""
    return sum(c.isdigit() for c in str(value))


def shape_of(value: str) -> str:
    """Classify a string without revealing it."""
    if UUID_RE.match(value):
        return "uuid"
    if ISO8601_RE.match(value):
        return "iso8601-datetime"
    if DATE_RE.match(value):
        return "iso8601-date"
    if URL_RE.match(value):
        return "url"
    if HEX_RE.match(value):
        return "hex"
    if DIGITS_RE.match(value):
        return "digits"
    if "@" in value and " " not in value:
        return "email-like"
    if "\n" in value:
        return "multiline-text"
    return "text"


def num_range_label(lo, hi) -> str:
    """A numeric range, or its digit widths when a bound could identify.

    ``num=4769238125..34175926611`` discloses two real record ids. The
    bounds are values, not shape, so they go through the same digit test
    the string gate applies. Below the threshold the bounds are printed,
    because a range like ``1..20`` is structure and suppressing it would
    make the report useless without making it safer.
    """
    if (digit_count(lo) >= IDENTIFYING_DIGITS
            or digit_count(hi) >= IDENTIFYING_DIGITS):
        return f"{digit_count(lo)}-digit..{digit_count(hi)}-digit"
    return f"{lo}..{hi}"


def looks_identifying(value: str) -> bool:
    """Whether a value could identify a person or thing, whatever its key.

    The key denylist is not enough on its own: a field nobody thought to
    name can still hold a phone number. This is the backstop, applied to
    every candidate value regardless of where it came from. Counts digits
    across the whole string rather than matching a numeric shape, so a
    punctuated or country-prefixed number is caught the same as a bare one.
    """
    if digit_count(value) >= IDENTIFYING_DIGITS:
        return True
    if UUID_RE.match(value) or HEX_RE.match(value) or ISO8601_RE.match(value):
        return True
    if DATE_RE.match(value) or URL_RE.match(value):
        return True
    if "@" in value:
        return True
    return False


class FieldStats:
    """Everything recorded about one key path."""

    __slots__ = ("types", "present", "nulls", "shapes", "values",
                 "overflowed", "min_len", "max_len", "min_num", "max_num")

    def __init__(self) -> None:
        self.types: Counter = Counter()
        self.present = 0
        self.nulls = 0
        self.shapes: Counter = Counter()
        self.values: set = set()
        self.overflowed = False
        self.min_len = None
        self.max_len = None
        self.min_num = None
        self.max_num = None

    def observe(self, value, max_enum: int) -> None:
        self.present += 1
        if value is None:
            self.nulls += 1
            self.types["null"] += 1
            return
        if isinstance(value, bool):
            self.types["bool"] += 1
            self._add_value("true" if value else "false", max_enum)
            return
        if isinstance(value, int):
            self.types["int"] += 1
            self.min_num = value if self.min_num is None else min(self.min_num, value)
            self.max_num = value if self.max_num is None else max(self.max_num, value)
            return
        if isinstance(value, float):
            self.types["float"] += 1
            return
        if isinstance(value, str):
            self.types["string"] += 1
            n = len(value)
            self.min_len = n if self.min_len is None else min(self.min_len, n)
            self.max_len = n if self.max_len is None else max(self.max_len, n)
            self.shapes[shape_of(value)] += 1
            self._add_value(value, max_enum)
            return
        if isinstance(value, list):
            self.types["array"] += 1
            n = len(value)
            self.min_len = n if self.min_len is None else min(self.min_len, n)
            self.max_len = n if self.max_len is None else max(self.max_len, n)
            return
        if isinstance(value, dict):
            self.types["object"] += 1
            return
        self.types["unknown"] += 1

    def _add_value(self, value: str, max_enum: int) -> None:
        if self.overflowed:
            return
        self.values.add(value)
        if len(self.values) > max_enum:
            self.overflowed = True
            self.values = set()

    def closed_set(self, leaf_key: str, max_enum: int):
        """The distinct values, if it is safe to print them. Else None."""
        if self.overflowed or not self.values:
            return None
        if leaf_key.lower() in CONTENT_KEYS:
            return None
        if len(self.values) > max_enum:
            return None
        for v in self.values:
            if not ENUM_VALUE_RE.match(v):
                return None
            if looks_identifying(v):
                return None
        return sorted(self.values)


class Walker:
    """Accumulates field stats over many JSON values."""

    def __init__(self, max_enum: int) -> None:
        self.max_enum = max_enum
        self.fields: dict = defaultdict(FieldStats)
        # How many object instances exist at each container path, so a
        # key's absent-count is derivable.
        self.containers: Counter = Counter()

    def walk(self, node, path: str) -> None:
        if isinstance(node, dict):
            self.containers[path] += 1
            for key in node:
                child = f"{path}.{key}" if path else key
                self.fields[child].observe(node[key], self.max_enum)
                self.walk(node[key], child)
        elif isinstance(node, list):
            child = f"{path}[]"
            for item in node:
                self.fields[child].observe(item, self.max_enum)
                self.walk(item, child)


def stream_json_array(fh, chunk_size: int = 1 << 20):
    """Yield elements of a top-level JSON array without loading it all.

    Falls back to a whole-document parse when the top level is not an
    array. Bounded memory is what makes this usable against a large
    conversations.json.
    """
    decoder = json.JSONDecoder()
    buf = ""
    idx = 0

    def fill() -> bool:
        nonlocal buf
        data = fh.read(chunk_size)
        if not data:
            return False
        buf += data.decode("utf-8", errors="replace")
        return True

    while True:
        while idx < len(buf) and buf[idx].isspace():
            idx += 1
        if idx < len(buf):
            break
        if not fill():
            return

    if buf[idx] != "[":
        # Not an array. Read the rest and parse as one document.
        while fill():
            pass
        yield json.loads(buf), False
        return

    idx += 1
    while True:
        while True:
            while idx < len(buf) and (buf[idx].isspace() or buf[idx] == ","):
                idx += 1
            if idx < len(buf):
                break
            if not fill():
                return
        if buf[idx] == "]":
            return
        while True:
            try:
                obj, end = decoder.raw_decode(buf, idx)
                break
            except ValueError:
                if not fill():
                    raise ValueError("truncated JSON array") from None
        yield obj, True
        buf = buf[end:]
        idx = 0


def safe_entry_name(name: str, digest: str) -> str:
    base = name.rsplit("/", 1)[-1]
    if SAFE_NAME_RE.match(base):
        return name
    prefix = name[: len(name) - len(base)]
    ext = base.rsplit(".", 1)[-1] if "." in base else "noext"
    ext = ext if re.match(r"^[A-Za-z0-9]{1,8}$", ext) else "noext"
    return f"{prefix}<redacted-{digest[:8]}>.{ext}"


def report_archive(path: str, max_enum: int, out) -> Walker:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    zip_digest = h.hexdigest()

    print(f"## archive {zip_digest[:16]}", file=out)
    print(f"sha256          {zip_digest}", file=out)

    walker = Walker(max_enum)
    with zipfile.ZipFile(path) as zf:
        infos = sorted(zf.infolist(), key=lambda i: i.filename)
        print(f"entries         {len(infos)}", file=out)
        print("", file=out)
        print("### inventory", file=out)
        print(f"{'entry':<44} {'uncompressed':>13} {'compressed':>11}", file=out)
        for info in infos:
            if info.is_dir():
                continue
            eh = hashlib.sha256(info.filename.encode("utf-8")).hexdigest()
            label = safe_entry_name(info.filename, eh)
            print(f"{label:<44} {info.file_size:>13} {info.compress_size:>11}",
                  file=out)
        print("", file=out)

        for info in infos:
            if info.is_dir() or not info.filename.lower().endswith(".json"):
                continue
            root = info.filename.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            root = root if re.match(r"^[A-Za-z0-9_-]+$", root) else "document"
            count = 0
            try:
                with zf.open(info) as fh:
                    for element, from_array in stream_json_array(fh):
                        count += 1
                        base = f"{root}[]" if from_array else root
                        walker.fields[base].observe(element, max_enum)
                        walker.walk(element, base)
            except ValueError as exc:
                # Message only, never the offending text.
                print(f"### {root}: parse failed ({type(exc).__name__})", file=out)
                continue
            print(f"### {root}: top-level elements {count}", file=out)
    print("", file=out)
    return walker


def print_fields(walker: Walker, max_enum: int, out) -> None:
    print("### fields", file=out)
    for path in sorted(walker.fields):
        st = walker.fields[path]
        parent = path.rsplit(".", 1)[0] if "." in path else ""
        leaf = path.rsplit(".", 1)[-1]
        parent_n = walker.containers.get(parent, 0)
        absent = max(0, parent_n - st.present) if parent_n else 0

        types = ",".join(f"{t}:{n}" for t, n in sorted(st.types.items()))
        bits = [f"present={st.present}", f"null={st.nulls}", f"absent={absent}",
                f"types={types}"]
        if st.shapes:
            bits.append("shapes=" + ",".join(
                f"{s}:{n}" for s, n in sorted(st.shapes.items())))
        if st.min_len is not None:
            bits.append(f"len={st.min_len}..{st.max_len}")
        if st.min_num is not None:
            bits.append("num=" + num_range_label(st.min_num, st.max_num))
        values = st.closed_set(leaf, max_enum)
        if values is not None:
            bits.append("values=[" + "|".join(values) + "]")
        print(f"{path}\n    " + " ".join(bits), file=out)
    print("", file=out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract structure (not content) from an Anthropic data export.")
    ap.add_argument("archives", nargs="+", help="export .zip files")
    ap.add_argument("--max-enum", type=int, default=MAX_ENUM_DEFAULT,
                    help="max distinct values before a field is treated as open-ended")
    ap.add_argument("--out", help="write report here instead of stdout")
    args = ap.parse_args()

    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        print("# anthropic export structure", file=out)
        print(f"max-enum        {args.max_enum}", file=out)
        print("", file=out)

        walkers = []
        for path in args.archives:
            walker = report_archive(path, args.max_enum, out)
            print_fields(walker, args.max_enum, out)
            walkers.append(walker)

        if len(walkers) > 1:
            merged = Walker(args.max_enum)
            for w in walkers:
                merged.containers.update(w.containers)
                for path, st in w.fields.items():
                    m = merged.fields[path]
                    m.types.update(st.types)
                    m.present += st.present
                    m.nulls += st.nulls
                    m.shapes.update(st.shapes)
                    if st.overflowed:
                        m.overflowed = True
                        m.values = set()
                    elif not m.overflowed:
                        m.values |= st.values
                        if len(m.values) > args.max_enum:
                            m.overflowed = True
                            m.values = set()
                    for attr, fn in (("min_len", min), ("max_len", max),
                                     ("min_num", min), ("max_num", max)):
                        a, b = getattr(m, attr), getattr(st, attr)
                        setattr(m, attr, b if a is None else (a if b is None else fn(a, b)))
            print("## merged", file=out)
            print_fields(merged, args.max_enum, out)
    finally:
        if args.out:
            out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
