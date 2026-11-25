# Read the record

Reconstruct what an agent did from the signed audit chain alone, offline, and verify nobody altered it.

## Set up

One terminal, and `sqlite3` installed.

## 1. Make a record

```
wirken ask -m "Write a file called notes.txt containing hello. Then use the exec tool to run: ls | wc -l"
```

A card asks about the pipeline. Type `n too risky` and press Enter.

Keep the reply that comes back. A small model may say it wrote the file, or give you the count, when it did neither.

## 2. Read it

```
wirken audit log --session default -n 40
wirken audit log --session default --format json --all > run.json
```

The table gives the order. `run.json` gives the detail: each entry of `events` is one row, its `action` is the row's name, and `detail` holds its fields. Find these rows in it:

| Row | What it holds |
| --- | --- |
| `user_message` | What was asked |
| `assistant_tool_calls` | The tool and the arguments, and in `text` the model's own words beside them, when it said any |
| `permission_denied` | The action key, who refused (`denied_by`, `stdin` for a card answered in `wirken ask`) and why (`denial_reason`) |
| `tool_result` | What came back to the model |
| `chain_head` | The signature over the rows before it |

Now hold the reply from step 1 against the rows. Was there a `write_file` call? Did the exec run?

## 3. Search it

```
wirken sessions search "wc"
```

Each hit names its session, its seq and its chain hash.

## 4. Verify it offline

Turn off Wi-Fi.

```
wirken audit verify --require-signed
```

You should see `Audit log integrity: OK`, and a warning that the signing key sits beside the log.

## 5. Break a copy

```
mkdir -p /tmp/wirken-copy
cp -r ~/.wirken/audit /tmp/wirken-copy/
sqlite3 ~/.wirken/audit.db ".backup /tmp/wirken-copy/audit.db"
export WIRKEN_DATA_DIR=/tmp/wirken-copy
sqlite3 $WIRKEN_DATA_DIR/audit.db "SELECT id, session_id, seq, substr(payload,1,60) FROM session_events WHERE payload LIKE '%wc -l%'"
sqlite3 $WIRKEN_DATA_DIR/audit.db "UPDATE session_events SET payload = replace(payload, 'ls | wc -l', 'ls') WHERE id = ID"
wirken audit verify
```

The copy is made with `.backup`, not `cp`: while `wirken run` is up, the newest rows sit in `audit.db-wal`, and a plain copy of `audit.db` comes out without them.

Replace `ID` with an id from the SELECT. You should see `Audit log integrity: BROKEN`, the session, and the seq where the chain broke: the session and seq of the row you edited. To go back to your real log: `unset WIRKEN_DATA_DIR`.

## 6. Now go further

- Run three more requests of your own and answer the cards differently each time. Clear your terminal, then rebuild all three from the record alone.
- Edit a different row in your copy and verify again. Does it name the right seq every time?
- Try harder edits on the copy: delete the last row, delete one from the middle, swap two payloads. Which does verify catch?
- Write the incident note: five sentences, each citing a session and a seq.

## Report back

What the record told you. One thing it could not tell you. Which edits verify caught.
