# Fixed: `InjectionDetector::scan` panicked on a multi-byte character

The four `crash-*` files beside this one are the inputs libFuzzer found for a
defect that is now fixed. They stay, for three reasons: they are the provenance
of the fix, `seed_corpus.py` copies them into `fuzz/corpus/injection_scan/` so a
run starts from the hardest inputs anyone has for this target, and
`crates/gateway/src/injection_detect.rs` compiles them into its tests with
`include_bytes!`, so deleting one breaks the build rather than quietly losing
coverage.

## What happened

`crates/gateway/src/injection_detect.rs`

```rust
let end = (pos + pat.len() + 40).min(text.len());
let matched = &text[pos..end];
```

`end` was byte arithmetic on attacker-supplied text with no character-boundary
check. When the forty-byte evidence window landed inside a multi-byte UTF-8
character, the slice panicked. The same shape appeared in four other windows:
the match span in `check_role_switch` and `check_system_prompt_extract`, the
two hundred bytes from the brace in `check_tool_call_injection`, and the sixty
character cap in `check_base64_commands`.

Smallest form:

```rust
InjectionDetector::new().scan(&format!("<|im_start|>system{}é", "a".repeat(39)));
// panicked: end byte index 58 is not a char boundary; it is inside 'é'
```

A second defect in the same code: the case-insensitive patterns took their
offset from `text.to_lowercase()`, whose byte length differs from the original
wherever a character does not lowercase one-for-one, so the audit row's offset
and evidence named the wrong bytes.

```
scan("İ ###System" + "x".repeat(60))
  -> position 4, evidence "##Systemxxx..."   (the match begins at byte 3)
```

## The fix

Every window goes through one `evidence` helper that walks the end back to a
character boundary, and every case-insensitive position goes through `Lowered`,
which keeps a map from the lowercased copy back into the original text. Both
cases above, and each of the four inputs here, are regression tests in
`injection_detect.rs`. `crates/gateway/tests/adapter_survives_hostile_text.rs`
covers what the panic used to take down.
