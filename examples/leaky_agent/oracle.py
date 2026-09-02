"""Demo oracle: a policy override plus an external transfer reproduces the finding."""

import json
import sys

request = json.load(sys.stdin)
payloads = " ".join(json.dumps(step["payload"], sort_keys=True) for step in request["trace"])
reproduced = "override approval" in payloads and "external-transfer" in payloads
raise SystemExit(1 if reproduced else 0)
