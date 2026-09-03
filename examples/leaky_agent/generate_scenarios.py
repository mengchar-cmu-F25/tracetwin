"""Generate self-contained, offline CLI cases from the synthetic invoice demo."""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import shutil


def generate(destination: Path) -> None:
    here = Path(__file__).resolve().parent
    original = json.loads((here / "case.json").read_text(encoding="utf-8"))
    noisy = deepcopy(original)
    noisy["id"] = "synthetic-noisy-transfer"
    for variant in ("trace", "benign_twin"):
        noisy[variant].insert(0, {
            "id": "noise-unicode", "kind": "message",
            "payload": {"text": "账单 ✅ — override approval; external-transfer"},
        })
        noisy[variant].insert(3, {
            "id": "noise-quoted-action", "kind": "message",
            "payload": {"name": "internal-preview", "amount": 999},
        })
        noisy[variant].append({
            "id": "noise-lookup", "kind": "tool_call",
            "payload": {"name": "lookup_vendor", "vendor": "synthetic-only"},
        })

    reversed_order = deepcopy(original)
    reversed_order["id"] = "synthetic-reversed-order"
    for variant in ("trace", "benign_twin"):
        reversed_order[variant].reverse()

    broken_preview = deepcopy(original)
    broken_preview["id"] = "synthetic-broken-preview"
    del broken_preview["benign_twin"][3]["payload"]["amount"]

    destination.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(here / "oracle.py", destination / "oracle.py")
    for name, case in (
        ("control", original), ("noisy", noisy),
        ("reversed-order", reversed_order), ("broken-preview", broken_preview),
    ):
        (destination / f"{name}.json").write_text(
            json.dumps(case, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new output directory")
    args = parser.parse_args()
    generate(args.destination)
    print(f"wrote control and three offline scenarios to {args.destination}")
