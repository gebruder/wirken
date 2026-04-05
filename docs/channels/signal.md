# Signal

```bash
wirken channel add signal
```

Signal requires [signal-cli](https://github.com/AsamK/signal-cli) running as a JSON-RPC daemon on the same machine.

1. Install signal-cli and register a phone number
2. Start signal-cli in daemon mode: `signal-cli -u +15551234567 daemon --json-rpc`
3. Enter the registered phone number and signal-cli endpoint when prompted

The adapter polls signal-cli's JSON-RPC interface for incoming messages and sends outbound messages via the `send` method.
