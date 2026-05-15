# iMessage (BlueBubbles)

```bash
wirken channel add imessage
```

iMessage requires [BlueBubbles Server](https://bluebubbles.app) running on a Mac with iMessage configured.

1. Install and configure BlueBubbles Server on a Mac
2. Note the server password and URL (default: `http://localhost:1234`)
3. Enter the server password and URL when prompted

The adapter registers a webhook with BlueBubbles for incoming messages and sends replies via the BlueBubbles REST API. Messages from yourself (`isFromMe`) are filtered out.

## Trust boundary and deployment constraint

BlueBubbles Server posts outbound webhook events with no authentication of any kind. The `axios.post` in [`webhookService/index.ts`](https://github.com/BlueBubblesApp/bluebubbles-server/blob/master/packages/server/src/server/services/webhookService/index.ts) sets only `Content-Type: application/json`. There is no HMAC signature, no bearer token, no shared secret in the body, no signed timestamp. The receiving side cannot verify a webhook came from BlueBubbles rather than from any process that can reach the adapter port.

The adapter therefore enforces its trust boundary at the socket layer:

- The webhook listener binds to `127.0.0.1` only. `wirken run` refuses to start the adapter if the bound local address is not a loopback IP.
- The realistic deployment is single-user, single-machine, with BlueBubbles Server and wirken on the same Mac.

If you need the adapter to receive webhooks from a different machine, put a trusted reverse proxy in front that adds its own authentication layer (mTLS, HMAC signing at the proxy, bearer header) and terminate that before the request reaches the loopback listener. Do not expose the adapter's port directly.

An upstream feature request for HMAC signing on BlueBubbles webhooks is tracked; if it lands, this adapter will adopt it and remove the loopback-only constraint.
