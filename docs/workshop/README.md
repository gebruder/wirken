# Workshop

Three hands-on exercises. Each starts from commands to copy, then leaves you to keep going on your own.

- [Write the rules](write-the-rules.md): build a permission policy and watch the gate allow, ask and refuse.
- [Read the record](read-the-record.md): reconstruct what an agent did from the signed audit chain, offline, and verify nobody altered it.
- [Break it](break-it.md): red team the gate and see what the record shows afterward.

Work on your own laptop. Nobody touches anyone else's. If Wirken isn't running on yours, sit beside someone whose is and follow along.

Before you start: Wirken installed, `wirken doctor` passing, Docker running, and Ollama with a small model.

The steps were checked with Wirken 3.5.1, Ollama serving `llama3.2:3b`, and Docker's default runtime. Another model may word its replies differently; the gate's answers do not change with the model.
