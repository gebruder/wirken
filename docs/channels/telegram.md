# Telegram

```bash
wirken channel add telegram
```

You need a bot token from [@BotFather](https://t.me/BotFather).

1. Message @BotFather on Telegram
2. Send `/newbot` and follow the prompts
3. Copy the bot token
4. Paste it when `wirken channel add telegram` prompts

The adapter uses long polling (no webhook URL needed). The bot responds to all private messages and can be added to groups.

Outbound markdown is rendered through `TelegramFormatter` from `wirken-adapter-core` and shipped with `parse_mode=HTML` on every send. HTML mode is the dialect choice: the escape surface is bounded to `<`, `>`, `&` (vs. fifteen-plus characters with strict positional rules in MarkdownV2), and the same converter is reused for the Matrix adapter with a different tag allowlist. Headings render as `<b>` (Telegram has no heading tag), bold/italic/strikethrough use `<b>`/`<i>`/`<s>`, inline and fenced code use `<code>` and `<pre><code class="language-…">`, blockquotes use `<blockquote>`, and tables flatten to `Header: value` lines. Replies use Telegram's `reply_parameters` with the inbound's `reply_to_message_id`; the gateway dispatcher carries that context through, so the bot's response targets the same message the user replied to. Root messages are not auto-replied-to.
