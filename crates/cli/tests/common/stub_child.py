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
  think         seconds the model takes to answer each call
  no_write_lifetime  leave out the lifetime of each step's cache write
  no_servers    leave the tool server list out of the opening message
  no_tool_id    call tools without the id of the tool use

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
    opening = {"type": "system", "subtype": "init",
               "tools": [prefix + t for t in listed] + scenario.get("tools", []),
               "mcp_servers": [{"name": server_name, "status": "connected"}],
               "model": pin, "apiKeySource": scenario.get("key_source", "none")}
    if scenario.get("no_servers"):
        del opening["mcp_servers"]
    emit(opening)

    think = scenario.get("think", 0)

    def step(n, content, stop, usage_out, call=None):
        """One model call. As the real binary does, a tool the reply
        names is called as soon as it is named, before the reply's own
        stream ends. `think` is how long the model takes to answer."""
        mid = "msg_%s_%d" % (os.getpid(), n)
        usage = {"input_tokens": 100 + n, "cache_read_input_tokens": 1000,
                 "cache_creation_input_tokens": 10, "output_tokens": 1}
        if not scenario.get("no_write_lifetime"):
            # Written to the cache for an hour, as the real binary does.
            usage["cache_creation"] = {"ephemeral_5m_input_tokens": 0,
                                       "ephemeral_1h_input_tokens": 10}
        message = {"id": mid, "model": model, "role": "assistant",
                   "content": content, "usage": usage, "stop_reason": None}
        if scenario.get("streamless"):
            time.sleep(think)
            usage["output_tokens"] = usage_out
            message["stop_reason"] = stop
            emit({"type": "assistant", "message": message})
            return call() if call else None
        time.sleep(think)
        emit({"type": "stream_event", "event": {
            "type": "message_start", "message": dict(message, content=[])}})
        emit({"type": "assistant", "message": message})
        answer = call() if call else None
        emit({"type": "stream_event", "event": {
            "type": "message_delta", "delta": {"stop_reason": stop},
            "usage": {"output_tokens": usage_out}}})
        emit({"type": "stream_event", "event": {"type": "message_stop"}})
        return answer

    n = 0
    for tool, arguments in scenario.get("calls", []):
        n += 1
        tool_id = "toolu_%d" % n
        answer = step(
            n,
            [{"type": "text", "text": "calling %s" % tool},
             {"type": "tool_use", "id": tool_id, "name": prefix + tool,
              "input": arguments}],
            "tool_use", 20 + n,
            lambda: rpc("tools/call", dict(
                {"name": tool, "arguments": arguments},
                **({} if scenario.get("no_tool_id")
                   else {"_meta": {"stub/toolUseId": tool_id}}))))
        record["answers"].append(answer.get("result", answer))
        emit({"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tool_id}]}})
    log()
    time.sleep(scenario.get("hang", 0))
    n += 1
    reply = scenario.get("reply", "done")
    step(n, [{"type": "text", "text": reply}], "end_turn", 30)
    emit({"type": "result", "subtype": "success", "is_error": False,
          "result": reply, "num_turns": n, "total_cost_usd": 0.0123,
          "duration_api_ms": int(think * 1000) * n,
          "usage": {"input_tokens": 100 * n, "output_tokens": 30 * n},
          "modelUsage": {model: {"inputTokens": 100 * n, "outputTokens": 400 * n,
                                 "cacheReadInputTokens": 1000 * n,
                                 "cacheCreationInputTokens": 10 * n,
                                 "costUSD": 0.0123}}})


main()
