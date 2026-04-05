# Microsoft Teams

```bash
wirken channel add teams
```

You need a Microsoft App ID and App Password from the [Azure Bot registration](https://portal.azure.com/#create/Microsoft.AzureBot).

1. Register a new bot in Azure
2. Note the App ID
3. Create a client secret (App Password)
4. Configure the messaging endpoint to point to your wirken instance (or use a tunnel for testing)

The adapter listens on `127.0.0.1:3978` for webhook callbacks from the Bot Framework.

In group chats, the bot only responds when mentioned. In 1:1 chats, it responds to all messages.
