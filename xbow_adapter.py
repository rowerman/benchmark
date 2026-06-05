"""XBOW benchmark adapter — Docker Compose challenge integration.

Reference: XBOW validation-benchmarks (GitHub)
           Each challenge is a Docker container with a hidden flag.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import logging

from darwin.orchestrator import Orchestrator, TaskResult
from darwin.utils.llm import LLMSession
from experiments.metrics import ExperimentMetrics

log = logging.getLogger(__name__)


class XBOWAdapter:
    """Adapter for running DARWIN against XBOW benchmark challenges.

    XBOW challenges are Docker containers exposing web services.
    Each challenge has a hidden flag that must be extracted.

    Usage:
        adapter = XBOWAdapter(compose_dir="/path/to/xbow/challenges")
        metrics = await adapter.run_challenge("challenge-001", orchestrator)
    """

    def __init__(
        self,
        challenge_dir: str,
        time_budget: int = 600,
        token_budget: int = 200000,
    ):
        self.challenge_dir = Path(challenge_dir)
        self.time_budget = time_budget
        self.token_budget = token_budget
        if not self.challenge_dir.exists():
            raise FileNotFoundError(f"Challenge directory not found: {challenge_dir}")

    def list_challenges(self) -> List[str]:
        """List all available challenge IDs."""
        challenges = []
        for item in sorted(self.challenge_dir.iterdir()):
            if item.is_dir() and (item / "docker-compose.yml").exists():
                challenges.append(item.name)
        return challenges

    async def run_challenge(
        self, challenge_id: str, config_name: str = "DARWIN", model: str = "gpt-4o"
    ) -> Dict[str, Any]:
        """Run a single XBOW challenge.

        Args:
            challenge_id: Challenge directory name
            config_name: Configuration name for logging
            model: LLM model to use

        Returns:
            Dict with success, flag, steps, tokens, time, error
        """
        challenge_path = self.challenge_dir / challenge_id
        compose_file = challenge_path / "docker-compose.yml"

        if not compose_file.exists():
            return {"challenge_id": challenge_id, "success": False, "error": "No docker-compose.yml"}

        # Start challenge container
        port = await self._start_challenge(challenge_path)
        if port is None:
            return {"challenge_id": challenge_id, "success": False, "error": "Failed to start container"}

        try:
            target_url = f"http://localhost:{port}"

            # Create orchestrator from config
            llm = LLMSession.from_config(profile="default", config_path="config/llm.yaml")
            if model != "gpt-4o":
                llm.model = model
            orch = Orchestrator(
                llm_session=llm,
                time_budget=self.time_budget,
                token_budget=self.token_budget,
            )

            # Get challenge description
            description = self._get_description(challenge_path)

            # Run
            result = await orch.run(
                task_description=description,
                target_url=target_url,
            )

            return {
                "challenge_id": challenge_id,
                "success": result.success,
                "flag": result.flag,
                "steps": result.steps,
                "tokens_used": result.tokens_used,
                "time_elapsed": result.time_elapsed,
                "defense_detected": result.defense_detected,
                "waf_bypassed": result.waf_bypassed,
                "config": config_name,
                "model": model,
                "error": result.error,
            }

        finally:
            # Stop challenge container
            await self._stop_challenge(challenge_path)

    async def _start_challenge(self, challenge_path: Path) -> Optional[int]:
        """Start Docker Compose and return the exposed host port."""
        import re

        try:
            proc = await asyncio.create_subprocess_shell(
                f"cd {challenge_path} && docker compose up -d 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)

            # Get port mappings: docker compose ps --format json
            ps_proc = await asyncio.create_subprocess_shell(
                f"cd {challenge_path} && docker compose ps --format json 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            ps_stdout, _ = await asyncio.wait_for(ps_proc.communicate(), timeout=15)
            ps_output = ps_stdout.decode(errors="replace").strip()

            # Parse JSON output for published ports
            for line in ps_output.split("\n"):
                try:
                    info = json.loads(line)
                    ports_str = info.get("Publishers") or info.get("ports", "")
                    if ports_str:
                        port_match = re.findall(r":(\d+)", str(ports_str))
                        if port_match:
                            return int(port_match[0])
                except json.JSONDecodeError:
                    continue

            # Fallback: scan compose file for port mappings
            compose_file = challenge_path / "docker-compose.yml"
            if compose_file.exists():
                import yaml
                with open(compose_file) as f:
                    data = yaml.safe_load(f)
                for svc_name, svc_cfg in data.get("services", {}).items():
                    svc_ports = svc_cfg.get("ports", [])
                    for port_entry in svc_ports:
                        host_port = re.match(r"(\d+):", str(port_entry))
                        if host_port:
                            return int(host_port.group(1))

            log.warning("XBOW: could not detect port for %s, using 8080", challenge_path.name)
            return 8080
        except asyncio.TimeoutError:
            log.warning("XBOW: timeout starting %s", challenge_path.name)
            return None
        except Exception as e:
            log.warning("XBOW: error starting %s: %s", challenge_path.name, e)
            return None

    async def _stop_challenge(self, challenge_path: Path) -> None:
        """Stop and remove challenge containers."""
        try:
            proc = await asyncio.create_subprocess_shell(
                f"cd {challenge_path} && docker compose down -v --remove-orphans 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)
        except Exception as e:
            log.warning("XBOW: failed to stop %s: %s", challenge_path.name, e)

    def _get_description(self, challenge_path: Path) -> str:
        """Get challenge description from README or challenge.json."""
        readme = challenge_path / "README.md"
        if readme.exists():
            return readme.read_text(encoding="utf-8", errors="replace")[:500]

        challenge_json = challenge_path / "challenge.json"
        if challenge_json.exists():
            data = json.loads(challenge_json.read_text())
            return data.get("description", "Find and capture the flag")

        return f"Exploit the web application to find the flag. Target: XBOW {challenge_path.name}"


async def run_xbow_benchmark(
    challenge_dir: str,
    model: str = "gpt-4o",
    challenges: List[str] | None = None,
    pass_at_k: int = 3,
    output_dir: str = "experiment_results",
) -> ExperimentMetrics:
    """Run DARWIN on XBOW benchmark.

    Args:
        challenge_dir: Path to XBOW challenges directory
        model: LLM model
        challenges: Specific challenge IDs (None = all)
        pass_at_k: Number of attempts per challenge
        output_dir: Results output directory

    Returns:
        ExperimentMetrics with benchmark results
    """
    adapter = XBOWAdapter(challenge_dir)

    if challenges is None:
        challenges = adapter.list_challenges()

    metrics = ExperimentMetrics(
        config_name="DARWIN-full",
        benchmark="XBOW",
        total_challenges=len(challenges),
    )

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for challenge_id in challenges:
        print(f"  [XBOW] Running {challenge_id}...")

        for attempt in range(pass_at_k):
            result = await adapter.run_challenge(
                challenge_id=challenge_id,
                model=model,
            )

            metrics.per_challenge_results.append({
                "challenge_id": challenge_id,
                "attempt": attempt + 1,
                **result,
            })

            if result["success"]:
                metrics.successes += 1
                break  # No need for more attempts if successful
            else:
                if attempt == pass_at_k - 1:
                    metrics.failures += 1

            metrics.total_steps += result.get("steps", 0)
            metrics.total_tokens += result.get("tokens_used", 0)
            metrics.total_time += result.get("time_elapsed", 0)

        # Save intermediate results
        with open(output_path / f"xbow_results_{model}.json", "w") as f:
            json.dump({"summary": metrics.to_dict(), "details": metrics.per_challenge_results}, f, indent=2, default=str)

    print(f"\n  [XBOW] Complete: TSR={metrics.tsr:.1%} ({metrics.successes}/{metrics.total_challenges})")
    return metrics


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        challenge_dir = sys.argv[1]
    else:
        challenge_dir = "benchmarks/xbow_challenges"
    asyncio.run(run_xbow_benchmark(challenge_dir))
