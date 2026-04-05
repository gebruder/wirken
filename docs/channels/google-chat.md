# Google Chat

```bash
wirken channel add google-chat
```

Google Chat requires a GCP project with the Chat API enabled and two things configured: a bearer token (so Wirken can send replies) and a webhook endpoint (so Google Chat can deliver inbound messages to Wirken).

## Create a Chat app

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Enable the [Google Chat API](https://console.cloud.google.com/apis/api/chat.googleapis.com)
4. Go to [Chat API configuration](https://console.cloud.google.com/apis/api/chat.googleapis.com/hangouts-chat)
5. Fill in the app name, avatar URL, and description
6. Under **Connection settings**, select **HTTP endpoint URL** (you'll fill this in after starting Wirken)

## Get a bearer token

For testing, use the gcloud CLI:

```bash
gcloud auth login
gcloud auth print-access-token
```

The token expires after ~60 minutes. Re-run `gcloud auth print-access-token` to get a new one.

Do not use `gcloud auth application-default login` -- it requires an OAuth consent screen configured with test users and will show "This app is blocked" unless that's set up.

## Add the channel

```bash
wirken channel add google-chat
```

Paste the bearer token when prompted. It is encrypted into the vault immediately.

## Expose the webhook

The adapter listens on `127.0.0.1:3980`. Google Chat needs to reach this over HTTPS.

For local testing, use [ngrok](https://ngrok.com/):

```bash
ngrok http 3980
```

Copy the HTTPS forwarding URL (e.g. `https://xxxx.ngrok-free.app`).

Go back to the [Chat API configuration](https://console.cloud.google.com/apis/api/chat.googleapis.com/hangouts-chat) and paste the ngrok URL into the HTTP endpoint URL field.

For production, point a public HTTPS endpoint at port 3980.

## How it works

The bearer token authenticates Wirken to the Chat REST API for sending replies. The webhook endpoint is how Google Chat delivers inbound messages to Wirken. Both are required -- without the token, Wirken can't respond; without the webhook, Wirken never receives messages.

## Test it

1. Start Wirken: `wirken run`
2. In a separate terminal: `ngrok http 3980`
3. Paste the ngrok URL into the Chat API configuration
4. Open Google Chat, find your app, send a message

The adapter logs show inbound messages at `RUST_LOG=debug wirken run`.
