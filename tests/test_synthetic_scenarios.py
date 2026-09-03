"""Offline end-to-end checks through the real CLI process, not cli.main()."""

import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys

import pytest

DEMO = Path(__file__).parents[1] / "examples" / "leaky_agent"


@pytest.fixture
def scenario_cli(tmp_path: Path):
    inputs = tmp_path / "case inputs"
    outputs = tmp_path / "artifact outputs"
    outputs.mkdir()
    caller = tmp_path / "unrelated caller"
    caller.mkdir()
    env = os.environ.copy()
    env.pop("TRACETWIN_DEMO_MODE", None)
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env["PATH"]
    env["PYTHONPATH"] = str(DEMO.parents[1] / "src")
    subprocess.run(
        [sys.executable, str(DEMO / "generate_scenarios.py"), str(inputs)],
        check=True, capture_output=True, text=True, env=env, cwd=caller,
    )

    def cli(*args, mode="vulnerable"):
        return subprocess.run(
            [sys.executable, "-m", "tracetwin.cli", *map(str, args)],
            capture_output=True, text=True, cwd=caller,
            env={**env, "TRACETWIN_DEMO_MODE": mode}, timeout=20,
        )

    return inputs, outputs, cli, env


def test_noisy_cli_pair_and_oracle_working_directory(scenario_cli) -> None:
    inputs, outputs, cli, env = scenario_cli
    control = outputs / "control.json"
    noisy = outputs / "noisy.json"
    for name, artifact, expected in (("control", control, 5), ("noisy", noisy, 8)):
        result = cli("minimize", inputs / f"{name}.json", "--output", artifact)
        assert result.returncode == 0, result.stderr
        assert f"{expected} -> 2 steps" in result.stdout
        replay_command = shlex.join(
            ["tracetwin", "replay", str(artifact), "--oracle-cwd", str(inputs)]
        )
        assert f"replay with: {replay_command}\n" in result.stdout
        replay = subprocess.run(
            shlex.split(replay_command), capture_output=True, text=True, env=env, timeout=20
        )
        assert replay.returncode == 0, replay.stderr
    pair = json.loads(noisy.read_text(encoding="utf-8"))
    baseline = json.loads(control.read_text(encoding="utf-8"))
    for variant in ("trace", "benign_twin"):
        assert pair[variant] == baseline[variant]
        assert [step["id"] for step in pair[variant]] == ["retrieval", "transfer"]

    # The artifact directory has no oracle: replay must not reuse the case cwd.
    missing = cli("replay", noisy)
    assert missing.returncode == 2
    assert "oracle exited 2" in missing.stderr and "oracle.py" in missing.stderr
    explicit = cli("replay", noisy, "--oracle-cwd", inputs)
    assert explicit.returncode == 0, explicit.stderr
    shutil.copyfile(inputs / "oracle.py", outputs / "oracle.py")
    default = cli("replay", noisy)
    assert default.returncode == 0, default.stderr

    for mode, expected, message in (
        ("vulnerable", 1, "attack trace still reproduces"),
        ("fixed", 0, "benign twin passed"),
        ("disable-all", 1, "benign twin did not pass"),
    ):
        result = cli("replay", noisy, "--expect-fixed", mode=mode)
        assert result.returncode == expected, result
        assert message in result.stdout + result.stderr


def test_reversed_operations_are_rejected_without_artifact(scenario_cli) -> None:
    inputs, outputs, cli, _ = scenario_cli
    artifact = outputs / "must-not-exist.json"
    result = cli("minimize", inputs / "reversed-order.json", "--output", artifact)
    assert result.returncode == 2
    assert "original trace did not reproduce" in result.stderr
    assert not artifact.exists()


def test_benign_execution_fault_is_not_a_security_verdict(scenario_cli) -> None:
    inputs, outputs, cli, env = scenario_cli
    broken = json.loads((inputs / "broken-preview.json").read_text(encoding="utf-8"))
    # Separately establish attack=PASS before the benign invocation really crashes.
    for variant, expected in (("attack", 0), ("benign", 2)):
        request = {
            "case_id": broken["id"], "variant": variant,
            "trace": broken["trace" if variant == "attack" else "benign_twin"],
            "metadata": broken["metadata"],
        }
        result = subprocess.run(
            [sys.executable, str(inputs / "oracle.py")], input=json.dumps(request),
            capture_output=True, text=True, cwd=inputs, timeout=5,
            env={**env, "TRACETWIN_DEMO_MODE": "fixed"},
        )
        assert result.returncode == expected, result
        assert ("demo oracle error: 'amount'" in result.stderr) == (variant == "benign")

    rejected = outputs / "must-not-exist.json"
    result = cli("minimize", inputs / "broken-preview.json", "--output", rejected)
    assert result.returncode == 2 and "oracle exited 2" in result.stderr
    assert not rejected.exists()

    # Fault-inject a valid generated artifact; this is not a successful reduction.
    artifact = outputs / "fault-injected.json"
    result = cli("minimize", inputs / "control.json", "--output", artifact)
    assert result.returncode == 0, result.stderr
    data = json.loads(artifact.read_text(encoding="utf-8"))
    del data["benign_twin"][1]["payload"]["amount"]
    artifact.write_text(json.dumps(data), encoding="utf-8")
    result = cli("replay", artifact, "--expect-fixed", "--oracle-cwd", inputs, mode="fixed")
    assert result.returncode == 2
    assert "oracle exited 2" in result.stderr and "demo oracle error: 'amount'" in result.stderr
    assert "replay passed" not in result.stdout


def test_same_directory_output_omits_replay_hint(scenario_cli) -> None:
    inputs, _, cli, _ = scenario_cli
    result = cli("minimize", inputs / "control.json")
    assert result.returncode == 0, result.stderr
    assert "replay with:" not in result.stdout
