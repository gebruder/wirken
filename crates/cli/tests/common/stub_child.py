#!/usr/bin/env python3
"""A stand-in for the agent binary a run on the child route starts.

It reads the flags a run passes, starts the tool server command named
in the tool server configuration, speaks the Model Context Protocol to
it, and writes the output stream a headless run writes. What it does is
set by the scenario file named in STUB_CHILD_SCENARIO, a JSON object:

  tools         extra tool names for the opening message
  key_source    the opening message's key source (default "none")
  model         the model reported on every step (default: the --model)
  calls         a list of [tool, arguments]: one step per call, each
                calling that tool through the tool server
  hang          seconds to sleep after the calls, before the result
  reply         the final reply text
  streamless    report steps from messages only, with no stream events

Every start is appended to STUB_CHILD_LOG as one JSON line: the
arguments, the working directory, the variables it was handed, the
prompt, the tool list the server gave and each tool call's answer.
"""
import json
import os
import subprocess
import sys
import time


def flag(name):
    args = sys.argv[1:]
    return args[args.index(name) + 1] if name in args else None


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    if "--version" in sys.argv:
        print("0.0.0 (stub child)")
        return
    scenario = json.load(open(os.environ["STUB_CHILD_SCENARIO"]))
    prompt = sys.stdin.read()
    config = json.load(open(flag("--mcp-config")))
    (server_name, server), = config["mcpServers"].items()
    proc = subprocess.Popen(
        [server["command"], *server["args"]],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    next_id = [0]

    def rpc(method, params=None, rid=None):
        next_id[0] += 1
        rid = rid if rid is not None else next_id[0]
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    # As the real client does: a discovery request an older server
    # answers with an error, then the opening exchange.
    discover = rpc("server/discover", {}, "server-discover-probe-1")
    rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "stub-child", "version": "0"}})
    proc.stdin.write(json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    proc.stdin.flush()
    listed = [t["name"] for t in rpc("tools/list")["result"]["tools"]]

    record = {
        "argv": sys.argv[1:],
        "cwd": os.getcwd(),
        "env": sorted(os.environ),
        "prompt": prompt,
        "system_prompt": open(flag("--system-prompt-file")).read(),
        "discover_was_refused": "error" in discover,
        "listed": listed,
        "answers": [],
    }

    def log():
        with open(os.environ["STUB_CHILD_LOG"], "a") as f:
            f.write(json.dumps(record) + "\n")

    pin = flag("--model")
    model = scenario.get("model", pin)
    prefix = "mcp__%s__" % server_name
    emit({"type": "system", "subtype": "init",
          "tools": [prefix + t for t in listed] + scenario.get("tools", []),
          "mcp_servers": [{"name": server_name, "status": "connected"}],
          "model": pin, "apiKeySource": scenario.get("key_source", "none")})

    def step(n, content, stop, usage_out):
        mid = "msg_%s_%d" % (os.getpid(), n)
        usage = {"input_tokens": 100 + n, "cache_read_input_tokens": 1000,
                 "cache_creation_input_tokens": 10, "output_tokens": 1}
        message = {"id": mid, "model": model, "role": "assistant",
                   "content": content, "usage": usage, "stop_reason": None}
        if scenario.get("streamless"):
            usage["output_tokens"] = usage_out
            message["stop_reason"] = stop
            emit({"type": "assistant", "message": message})
            return
        emit({"type": "stream_event", "event": {
            "type": "message_start", "message": dict(message, content=[])}})
        emit({"type": "assistant", "message": message})
        emit({"type": "stream_event", "event": {
            "type": "message_delta", "delta": {"stop_reason": stop},
            "usage": {"output_tokens": usage_out}}})
        emit({"type": "stream_event", "event": {"type": "message_stop"}})

    n = 0
    for tool, arguments in scenario.get("calls", []):
        n += 1
        step(n, [{"type": "text", "text": "calling %s" % tool},
                 {"type": "tool_use", "id": "toolu_%d" % n, "name": prefix + tool,
                  "input": arguments}], "tool_use", 20 + n)
        answer = rpc("tools/call", {"name": tool, "arguments": arguments,
                                    "_meta": {"stub/toolUseId": "toolu_%d" % n}})
        record["answers"].append(answer.get("result", answer))
        emit({"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_%d" % n}]}})
    log()
    time.sleep(scenario.get("hang", 0))
    n += 1
    reply = scenario.get("reply", "done")
    step(n, [{"type": "text", "text": reply}], "end_turn", 30)
    emit({"type": "result", "subtype": "success", "is_error": False,
          "result": reply, "num_turns": n, "total_cost_usd": 0.0123,
          "usage": {"input_tokens": 100 * n, "output_tokens": 30 * n},
          "modelUsage": {model: {"inputTokens": 100 * n, "outputTokens": 30 * n,
                                 "cacheReadInputTokens": 1000 * n,
                                 "cacheCreationInputTokens": 10 * n,
                                 "costUSD": 0.0123}}})


main()
