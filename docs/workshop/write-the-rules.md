# Write the rules

Build a permission policy for your own agent use case, then watch the gate allow, ask and refuse.

## Set up

Open three terminals.

```
# Terminal A: the gateway
wirken run

# Terminal B: the chat
wirken chat

# Terminal C: you, the operator
wirken permissions list --agent default
```

## 1. See the four answers

Type these into the chat, one at a time. Answer `n` on every card.

```
Write a file called notes.txt in your workspace containing the word hello.
Use the exec tool to run this command: ls -la
Use the exec tool to run this command: ls | wc -l
Use the http_request tool to GET https://example.com/
```

| Message | What the gate does |
| --- | --- |
| 1 | Allows it. No card. Workspace files never ask. |
| 2 | Asks. Action key `shell:ls`, tier 2. |
| 3 | Asks. Action key `shell::pipeline:`, tier 3. |
| 4 | Refuses. No card. The host is on nobody's allow-list. |

If the model answers in words instead of acting, tell it again: "Use the exec tool."

To read back what scrolled past, use PgUp and PgDn (Fn+↑ and Fn+↓ on a Mac laptop). From 3.5.3 the arrow keys, the mouse wheel and the trackpad scroll too, and End returns to the latest line.

After a refusal the model may still answer as if the command ran, even with made-up output. The tool line above its reply says what the gate did.

## 2. Write a rule

In terminal C:

```
wirken permissions approve shell:ls --agent default --channel terminal --expires-in-days 1
wirken permissions list --agent default
```

Send message 2 again. No card this time.

## 3. Find the edge of the rule

```
wirken permissions approve shell:bash --agent default --channel terminal
wirken permissions approve 'shell::pipeline:' --agent default --channel terminal
```

Both are refused. Only these verbs can be stored:

```
ls cat head tail grep diff cmp stat wc
readlink realpath basename dirname
pwd whoami id uname hostname date echo printf which type
```

## 4. Pull the plug

```
wirken agents stop default --revoke-all
```

Send any message. Nothing runs: the gateway refuses it before the model sees it, and the chat shows the refusal and its reason, `agent_stopped`. Your grant from step 2 is gone; `wirken permissions list --agent default` shows none. Then bring the agent back:

```
wirken agents resume default
```

Send message 2 again in the same chat. The card is back.

On a release before 3.5.2 the chat waits for a reply that never comes: leave with Ctrl+C and start `wirken chat` again.

## 5. Now your own agent

- Pick a job: a legal aid office's case-file assistant, a union local's newsletter drafter, or your own.
- List ten actions it needs. Before you run each one, write down your guess: allow, ask or refuse.
- Run them in the chat. Mark every wrong guess.
- Grant what you would trust for one day. Leave the rest asking.
- Ask your neighbour for messages that might get past your policy. You type them yourself, on your own laptop.
- In the chat, `/approvals` shows your grants and `/verify` checks the conversation's chain.

## Report back

Your ten actions in three columns. The guess you got wrong. The rule you wanted and could not write.
