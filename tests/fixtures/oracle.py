import json
import sys

request = json.load(sys.stdin)
tokens = {step["payload"].get("token") for step in request["trace"]}
if "alpha" in tokens and "omega" in tokens:
    raise SystemExit(1)
raise SystemExit(0)
