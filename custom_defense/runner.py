"""Custom Defense Benchmark Runner — runs DARWIN against defense challenges.

Usage:
    python3 -m benchmarks.custom_defense.runner cloak-01
    python3 -m benchmarks.custom_defense.runner --category cloak
    python3 -m benchmarks.custom_defense.runner --all
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

from benchmarks.custom_defense.challenges import (
    CHALLENGES, start_challenge, stop_challenge, get_challenge_config,
)
from darwin.orchestrator import Orchestrator, TaskResult
from darwin.utils.llm import LLMSession
from experiments.metrics import ExperimentMetrics, compute_pass_at_k


async def run_one_challenge(
    challenge_id: str,
    pass_at_k: int = 1,
    time_budget: int = 300,
    token_budget: int = 100000,
    output_dir: str = "experiment_results/custom_defense",
) -> List[Dict]:
    """Run DARWIN against one Custom Defense challenge.

    Returns list of attempt result dicts.
    """
    cfg = get_challenge_config(challenge_id)
    if cfg is None:
        print(f"Unknown challenge: {challenge_id}")
        return []

    # Start challenge server
    server, thread, port = start_challenge(challenge_id, cfg)
    target_url = f"http://localhost:{port}"
    print(f"\n{'='*60}")
    print(f"Challenge: {challenge_id}")
    print(f"  Defense:  {cfg['defense']}/{cfg['subtype']}")
    print(f"  Vuln:     {cfg['vuln']}")
    print(f"  Target:   {target_url}")
    print(f"{'='*60}")

    results = []
    for attempt in range(pass_at_k):
        print(f"\n  Attempt {attempt+1}/{pass_at_k}...")

        llm = LLMSession.from_config(profile="default", config_path="config/llm.yaml")
        orch = Orchestrator(
            llm_session=llm,
            time_budget=time_budget,
            token_budget=token_budget,
        )

        try:
            result = await orch.run(
                task_description=cfg["description"],
                target_url=target_url,
            )
        except Exception as e:
            result = TaskResult(success=False, error=str(e))

        attempt_data = {
            "challenge_id": challenge_id,
            "attempt": attempt + 1,
            "success": result.success,
            "flag": result.flag,
            "steps": result.steps,
            "tokens_used": result.tokens_used,
            "time_elapsed": round(result.time_elapsed, 1),
            "defense_detected": result.defense_detected,
            "waf_bypassed": result.waf_bypassed,
            "waf_type": result.waf_type,
            "error": result.error,
        }
        results.append(attempt_data)

        status = "SUCCESS" if result.success else "FAILED"
        print(f"  {status}: flag={result.flag or 'none'}, steps={result.steps}, "
              f"tokens={result.tokens_used}, time={result.time_elapsed:.1f}s")

        if result.success:
            break  # don't need more attempts

    # Stop challenge
    stop_challenge(server)
    time.sleep(0.5)

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    result_path = os.path.join(output_dir, f"{challenge_id}.json")
    with open(result_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    return results


async def run_category(
    category: str,
    pass_at_k: int = 1,
    time_budget: int = 300,
    token_budget: int = 100000,
    output_dir: str = "experiment_results/custom_defense",
) -> ExperimentMetrics:
    """Run all challenges in a defense category."""
    challenge_ids = [cid for cid, cfg in CHALLENGES.items()
                     if cfg["defense"] == category]

    metrics = ExperimentMetrics(
        config_name=f"DARWIN-full",
        benchmark=f"CustomDefense-{category}",
        total_challenges=len(challenge_ids),
    )

    per_challenge_runs: Dict[str, List[bool]] = {}

    for cid in sorted(challenge_ids):
        results = await run_one_challenge(
            cid, pass_at_k=pass_at_k,
            time_budget=time_budget, token_budget=token_budget,
            output_dir=output_dir,
        )

        challenge_successes = [r["success"] for r in results]
        per_challenge_runs[cid] = challenge_successes

        if any(challenge_successes):
            metrics.successes += 1
        else:
            metrics.failures += 1

        for r in results:
            metrics.total_steps += r.get("steps", 0)
            metrics.total_tokens += r.get("tokens_used", 0)
            metrics.total_time += r.get("time_elapsed", 0)

    pass_score = compute_pass_at_k(per_challenge_runs, pass_at_k)
    print(f"\n{metrics.summary()}, Pass@{pass_at_k}={pass_score:.1%}")

    return metrics


async def run_all(
    pass_at_k: int = 1,
    output_dir: str = "experiment_results/custom_defense",
) -> Dict[str, ExperimentMetrics]:
    """Run all 20 Custom Defense challenges."""
    metrics = {}
    for category in ["cloak", "honey", "trap", "combined"]:
        print(f"\n{'#'*60}\n# Custom Defense — {category.upper()}\n{'#'*60}")
        m = await run_category(
            category, pass_at_k=pass_at_k, output_dir=output_dir,
        )
        metrics[category] = m
    return metrics


def main():
    parser = argparse.ArgumentParser(description="DARWIN Custom Defense Benchmark Runner")
    parser.add_argument("challenge", nargs="?", help="Challenge ID (e.g. cloak-01)")
    parser.add_argument("--category", help="Run all in category: cloak|honey|trap|combined")
    parser.add_argument("--all", action="store_true", help="Run all 20 challenges")
    parser.add_argument("--pass-at-k", type=int, default=1, help="Attempts per challenge")
    parser.add_argument("--output-dir", default="experiment_results/custom_defense")
    args = parser.parse_args()

    if args.all:
        asyncio.run(run_all(pass_at_k=args.pass_at_k, output_dir=args.output_dir))
    elif args.category:
        if args.category not in ("cloak", "honey", "trap", "combined"):
            print(f"Invalid category: {args.category}")
            sys.exit(1)
        asyncio.run(run_category(
            args.category, pass_at_k=args.pass_at_k, output_dir=args.output_dir,
        ))
    elif args.challenge:
        asyncio.run(run_one_challenge(
            args.challenge, pass_at_k=args.pass_at_k, output_dir=args.output_dir,
        ))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
