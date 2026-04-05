# iMessage (BlueBubbles)

```bash
wirken channel add imessage
```

iMessage requires [BlueBubbles Server](https://bluebubbles.app) running on a Mac with iMessage configured.

1. Install and configure BlueBubbles Server on a Mac
2. Note the server password and URL (default: `http://localhost:1234`)
3. Enter the server password and URL when prompted

The adapter registers a webhook with BlueBubbles for incoming messages and sends replies via the BlueBubbles REST API. Messages from yourself (`isFromMe`) are filtered out.
