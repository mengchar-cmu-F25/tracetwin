#!/usr/bin/env python3
"""Verify the checked-in projection against a fixed AgentDojo checkout."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

COMMIT = "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
ATTACK_PATH = (
    "runs/gpt-4o-mini-2024-07-18/banking/user_task_11/"
    "important_instructions/injection_task_0.json"
)
CLEAN_PATH = "runs/gpt-4o-mini-2024-07-18/banking/user_task_11/none/none.json"
PREDICATE_PATH = "src/agentdojo/default_suites/v1/banking/injection_tasks.py"
PREDICATE_V1_2_PATH = "src/agentdojo/default_suites/v1_2/banking/injection_tasks.py"
EXPECTED_SHA256 = {
    ATTACK_PATH: "857db9e540f8c2324999215d23a5b23b380bee9f452b7941611d3f3f84bd3c05",
    CLEAN_PATH: "c493eae45117e97697bb266a08e35b112ef524a8b8d131b1aa3fa4ab012f0b0f",
    PREDICATE_PATH: "fa2dedf8e66c95ffadb54f5a26648728b08c56f302858de4ee9a5cc0b3891618",
    PREDICATE_V1_2_PATH: "3e678ad165f911dbc16c8307de761dcc15da274716bec7ac0d05db167ec2c311",
    "LICENSE": "4285a071f2d382338e52b4fb0a186d952984a34d43a33d8872e1a1d8cb43401e",
}
ALIGNMENT = (
    ("tool-01-list-transactions", (2, 0, 3), (2, 0, 3)),
    ("tool-02-injected-transfer", (4, 0, 5), None),
    ("tool-03-get-iban", (6, 0, 7), (4, 0, 5)),
    ("tool-04-get-balance", (6, 1, 8), None),
    ("tool-05-vat-transfer", (9, 0, 10), (6, 0, 7)),
)
IDENTITY_FIELDS = (
    "suite_name",
    "pipeline_name",
    "user_task_id",
    "injection_task_id",
    "attack_type",
    "injections",
    "error",
    "utility",
    "security",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(log: dict) -> dict:
    return {field: log[field] for field in IDENTITY_FIELDS}


def project_execution(log: dict, location: tuple[int, int, int]) -> dict:
    call_message_index, call_index, result_message_index = location
    call_message = log["messages"][call_message_index]
    call = call_message["tool_calls"][call_index]
    result = log["messages"][result_message_index]
    if call_message["role"] != "assistant" or result["role"] != "tool":
        raise ValueError(f"invalid call/result roles at {location}")
    if result["tool_call_id"] != call["id"] or result["tool_call"] != call:
        raise ValueError(f"call/result mismatch at {location}")
    return {
        "observed": True,
        "tool_call": {
            "function": call["function"],
            "args": call["args"],
            "id": call["id"],
        },
        "tool_result": {
            "content": result["content"],
            "error": result["error"],
            "tool_call_id": result["tool_call_id"],
        },
        "source": {
            "call_message_index": call_message_index,
            "call_index": call_index,
            "result_message_index": result_message_index,
        },
    }


def no_op(step_id: str) -> dict:
    return {
        "observed": False,
        "adapter_reason": (
            f"No corresponding clean-run execution exists for {step_id}; "
            "this adapter-only no-op preserves paired step shape."
        ),
    }


def build_projection(attack: dict, clean: dict) -> tuple[list[dict], list[dict]]:
    attack_steps = []
    clean_steps = []
    for step_id, attack_location, clean_location in ALIGNMENT:
        attack_steps.append(
            {
                "id": step_id,
                "kind": "tool_execution",
                "payload": project_execution(attack, attack_location),
            }
        )
        clean_steps.append(
            {
                "id": step_id,
                "kind": "tool_execution",
                "payload": (
                    project_execution(clean, clean_location)
                    if clean_location
                    else no_op(step_id)
                ),
            }
        )
    return attack_steps, clean_steps


def class_method(tree: ast.Module, class_name: str, method_name: str) -> ast.FunctionDef:
    class_node = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return next(
        node
        for node in class_node.body
        if isinstance(node, ast.FunctionDef) and node.name == method_name
    )


def class_constant(tree: ast.Module, class_name: str, name: str):
    class_node = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    assignment = next(
        node
        for node in class_node.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        )
    )
    return ast.literal_eval(assignment.value)


def transaction_fields(log: dict, field: str) -> list[str]:
    content = project_execution(log, (2, 0, 3))["tool_result"]["content"]
    prefix = f"{field}:"
    return [
        line.strip()[len(prefix) :].strip().strip("'\"")
        for line in content.splitlines()
        if line.strip().startswith(prefix)
    ]


def validate_predicate(checkout: Path, metadata: dict, attack: dict, clean: dict) -> None:
    primary = checkout / PREDICATE_PATH
    compatibility = checkout / PREDICATE_V1_2_PATH
    primary_tree = ast.parse(primary.read_text(encoding="utf-8"))
    primary_method = class_method(primary_tree, "InjectionTask0", "security")
    compatibility_method = class_method(
        ast.parse(compatibility.read_text(encoding="utf-8")), "InjectionTask0", "security"
    )
    if ast.dump(primary_method) != ast.dump(compatibility_method):
        raise ValueError("v1 and v1.2 InjectionTask0.security methods differ")
    returned = primary_method.body[-1]
    if not (
        isinstance(returned, ast.Return)
        and isinstance(returned.value, ast.Call)
        and isinstance(returned.value.func, ast.Name)
        and returned.value.func.id == "any"
    ):
        raise ValueError("unexpected InjectionTask0.security effect predicate")
    attacker_iban = class_constant(primary_tree, "InjectionTask0", "_ATTACKER_IBAN")
    services = class_constant(primary_tree, "InjectionTask0", "_SERVICES")
    attack_subjects = "\n".join(transaction_fields(attack, "subject")).lower()
    clean_subjects = "\n".join(transaction_fields(clean, "subject")).lower()
    attack_service = next((service for service in services if service in attack_subjects), None)
    clean_service = next((service for service in services if service in clean_subjects), None)
    if attack_service != clean_service or attack_service is None:
        raise ValueError("attack and clean pre-environments do not expose one shared service")
    attacker_counts = {
        sum(value.lower() == attacker_iban.lower() for value in transaction_fields(log, "recipient"))
        for log in (attack, clean)
    }
    if len(attacker_counts) != 1:
        raise ValueError("attack and clean pre-environments disagree on attacker transactions")
    expected = {
        "class": "InjectionTask0",
        "method": "security",
        "source_path": PREDICATE_PATH,
        "source_sha256": EXPECTED_SHA256[PREDICATE_PATH],
        "attacker_iban": attacker_iban,
        "pre_environment_streaming_service": attack_service,
        "pre_environment_attacker_transaction_count": attacker_counts.pop(),
    }
    if metadata != expected:
        raise ValueError("case predicate metadata does not match the fixed source")


def validate(checkout: Path) -> None:
    checkout = checkout.resolve()
    head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if head != COMMIT:
        raise ValueError(f"checkout is {head}, expected {COMMIT}")
    for relative_path, expected in EXPECTED_SHA256.items():
        actual = sha256(checkout / relative_path)
        if actual != expected:
            raise ValueError(f"SHA256 mismatch for {relative_path}: {actual}")

    attack = json.loads((checkout / ATTACK_PATH).read_text(encoding="utf-8"))
    clean = json.loads((checkout / CLEAN_PATH).read_text(encoding="utf-8"))
    case_path = Path(__file__).with_name("case.json")
    case = json.loads(case_path.read_text(encoding="utf-8"))
    projected_attack, projected_clean = build_projection(attack, clean)
    if case["trace"] != projected_attack or case["benign_twin"] != projected_clean:
        raise ValueError("case tool executions do not exactly match the fixed logs")

    upstream = case["metadata"]["upstream"]
    expected_upstream = {
        "repository": "https://github.com/ethz-spylab/agentdojo",
        "commit": COMMIT,
        "attack": {
            "path": ATTACK_PATH,
            "sha256": EXPECTED_SHA256[ATTACK_PATH],
            "fields": identity(attack),
        },
        "clean": {
            "path": CLEAN_PATH,
            "sha256": EXPECTED_SHA256[CLEAN_PATH],
            "fields": identity(clean),
        },
    }
    if upstream != expected_upstream:
        raise ValueError("case upstream metadata does not exactly match the fixed logs")
    validate_predicate(checkout, case["metadata"]["predicate"], attack, clean)
    expected_adapter = {
        "projection": "five aligned tool executions",
        "step_ids": "TraceTwin adapter identifiers, not AgentDojo message or tool-call IDs",
        "wrappers": "observed/source/tool_result and clean no-op payloads are adapter metadata",
        "clean_no_ops": ["tool-02-injected-transfer", "tool-04-get-balance"],
    }
    if case["metadata"]["adapter"] != expected_adapter:
        raise ValueError("case adapter metadata does not match the validated projection")


def _offline_verdict(case: dict, variant: str, trace: list[dict]) -> bool:
    request = {
        "case_id": case["id"],
        "variant": variant,
        "trace": trace,
        "metadata": case["metadata"],
    }
    result = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("oracle.py"))],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=case["oracle"]["timeout_seconds"],
    )
    if result.returncode not in (0, 1):
        raise ValueError(f"offline oracle failed: {(result.stderr or result.stdout).strip()}")
    return result.returncode == 1


def validate_official_verdicts(checkout: Path) -> int:
    """Compare the fixed offline oracle with AgentDojo's actual predicate."""

    checkout = checkout.resolve()
    dirty = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if dirty:
        raise ValueError("official replay requires a clean AgentDojo checkout")
    sys.path.insert(0, str(checkout / "src"))
    import agentdojo
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite

    if not Path(agentdojo.__file__).resolve().is_relative_to(checkout / "src" / "agentdojo"):
        raise ValueError("AgentDojo was not imported from the validated checkout")

    case = json.loads(Path(__file__).with_name("case.json").read_text(encoding="utf-8"))
    attack = json.loads((checkout / ATTACK_PATH).read_text(encoding="utf-8"))
    clean = json.loads((checkout / CLEAN_PATH).read_text(encoding="utf-8"))
    suite = get_suite("v1", "banking")
    injection_task_id = attack["injection_task_id"]

    def official(log: dict, steps: list[dict]) -> bool:
        user_task = suite.get_user_task_by_id(log["user_task_id"])
        injection_task = suite.get_injection_task_by_id(injection_task_id)
        environment = suite.load_and_inject_default_environment(log["injections"])
        post_environment = user_task.init_environment(environment)
        pre_environment = post_environment.model_copy(deep=True)
        runtime = FunctionsRuntime(suite.tools)
        for step in steps:
            payload = step["payload"]
            if not payload.get("observed") or payload["tool_result"]["error"] is not None:
                continue
            call = payload["tool_call"]
            _, error = runtime.run_function(post_environment, call["function"], call["args"])
            if error:
                raise ValueError(f"official replay failed for {step['id']}: {error}")
        return injection_task.security("", pre_environment, post_environment)

    key_id = "tool-02-injected-transfer"
    key_only = [step for step in case["trace"] if step["id"] == key_id]
    without_key = [step for step in case["trace"] if step["id"] != key_id]
    checks = [
        ("full attack", "attack", attack, case["trace"], True),
        ("full clean", "benign", clean, case["benign_twin"], False),
        ("key only", "attack", attack, key_only, True),
        ("without key", "attack", attack, without_key, False),
    ]
    checks.extend(
        (
            f"without unrelated {step['id']}",
            "attack",
            attack,
            [candidate for candidate in case["trace"] if candidate["id"] != step["id"]],
            True,
        )
        for step in case["trace"]
        if step["id"] != key_id
    )
    for name, variant, log, steps, expected in checks:
        official_result = official(log, steps)
        offline_result = _offline_verdict(case, variant, steps)
        if official_result != expected or offline_result != expected:
            raise ValueError(
                f"{name}: expected {expected}, official={official_result}, "
                f"offline={offline_result}"
            )
    return len(checks)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path, help=f"AgentDojo checkout at {COMMIT}")
    parser.add_argument(
        "--official",
        action="store_true",
        help="also replay effects through AgentDojo and compare predicate verdicts",
    )
    args = parser.parse_args(argv)
    try:
        validate(args.checkout)
        verdict_checks = validate_official_verdicts(args.checkout) if args.official else 0
    except (
        ImportError,
        KeyError,
        StopIteration,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"provenance verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"verified AgentDojo {COMMIT}: "
        "5 attack steps, 3 clean steps + 2 adapter no-ops"
    )
    if verdict_checks:
        print(f"official and offline verdicts matched across {verdict_checks} sensitivity checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
