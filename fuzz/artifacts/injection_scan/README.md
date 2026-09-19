# Open finding: `InjectionDetector::scan` panics on a multi-byte character

The four `crash-*` files beside this one are libFuzzer reproducers for one
defect. They stay here until it is fixed. Running the target rediscovers it
within a few thousand executions, so the `Fuzz` CI job is red for
`injection_scan` in the meantime. That is the tripwire working, not a flake.

## What happens

`crates/gateway/src/injection_detect.rs:198`

```rust
let end = (pos + pat.len() + 40).min(text.len());
let matched = &text[pos..end];
```

`end` is arithmetic on byte offsets with no character-boundary check. When the
forty-byte evidence window lands inside a multi-byte UTF-8 character, the slice
panics.

Smallest reproducer, no fuzzer needed:

```rust
InjectionDetector::new().scan(&format!("<|im_start|>system{}é", "a".repeat(39)));
```

```
panicked at crates/gateway/src/injection_detect.rs:198:36:
end byte index 58 is not a char boundary; it is inside 'é' (bytes 57..59 of string)
```

`check_instruction_override` is the site the fuzzer reached. `pos + pat.len() + 40`
appears in the other `check_*` helpers too, so the fix belongs at all of them.

## Why it matters

`scan` runs on every inbound channel message, before the agent sees it, on text
from anyone who can reach an adapter. The trigger is a pattern the detector
already looks for followed by a non-ASCII character at the right offset, which
is ordinary text in most languages. Reaching it needs no account, no approval
and no tool call.

## Related, same function, not a panic

The case-insensitive patterns (`###System`, `<system>`, `</system>`) take their
position from `text.to_lowercase()`, whose byte length can differ from `text`.
The offset and the evidence are then both shifted relative to the message the
audit row names:

```
scan("İ ###System" + "x".repeat(60))
  -> position 4, evidence "##Systemxxx..."   (the match begins at byte 3)
scan("I ###System" + "x".repeat(60))
  -> position 2, evidence "###Systemxxx..."  (correct)
```

Detection still fires, so this is wrong evidence rather than a bypass.
