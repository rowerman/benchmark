"""PACEBench adapter — implements the 4-endpoint HTTP server protocol.

Reference: PACEBench docs/agent_server_protocol.md

Endpoints:
  POST /model  — select LLM model
  POST /chat   — receive task prompt, start pentest
  GET  /result — poll for progress or final flag
  POST /stop   — terminate current task
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from darwin.orchestrator import Orchestrator, TaskResult, OrchestratorPhase
from darwin.utils.llm import LLMSession


# ── Pydantic Models ─────────────────────────────────────────────────

class ModelRequest(BaseModel):
    model: str

class ModelResponse(BaseModel):
    status: str = "ok"

class ChatRequest(BaseModel):
    prompt: str

class ChatResponse(BaseModel):
    status: str = "ok"

class ResultResponse(BaseModel):
    flag: str = ""
    step: int = 0
    total: int = 0
    duration: float = 0.0
    total_tokens: int = 0
    total_cost: float = 0.0
    done: bool = False
    status: str = "running"


# ── FastAPI App ────────────────────────────────────────────────────

app = FastAPI(title="DARWIN PACEBench Adapter", version="0.1.0")

# Global state
orchestrator: Optional[Orchestrator] = None
current_model: str = "gpt-4o"
task_running: bool = False
last_result: Optional[TaskResult] = None
task_start_time: float = 0.0


@app.post("/model")
async def select_model(req: ModelRequest) -> ModelResponse:
    """Select the LLM model to use."""
    global current_model
    current_model = req.model
    return ModelResponse(status="ok")


@app.post("/chat")
async def receive_task(req: ChatRequest) -> ChatResponse:
    """Receive a penetration test task and start execution."""
    global orchestrator, task_running, last_result, task_start_time

    if task_running:
        raise HTTPException(status_code=409, detail="Task already running")

    # Parse target URL from prompt (PACEBench includes target URL in the prompt)
    target_url = _extract_target_url(req.prompt)

    # Initialize orchestrator from config
    llm = LLMSession.from_config(profile="default", config_path="config/llm.yaml")
    if current_model and current_model != "gpt-4o":
        llm.model = current_model  # override if model was explicitly selected
    orchestrator = Orchestrator(
        llm_session=llm,
        time_budget=600,
        token_budget=200000,
    )

    task_running = True
    task_start_time = time.time()
    last_result = None

    # Run asynchronously
    asyncio.create_task(_run_task(req.prompt, target_url))

    return ChatResponse(status="ok")


@app.get("/result")
async def get_result() -> ResultResponse:
    """Poll for current progress or final result."""
    global last_result, task_running, task_start_time

    if not task_running and last_result is None:
        return ResultResponse(status="idle")

    duration = time.time() - task_start_time

    if last_result is not None:
        return ResultResponse(
            flag=last_result.flag,
            step=last_result.steps,
            total=last_result.steps,
            duration=duration,
            total_tokens=last_result.tokens_used,
            total_cost=_estimate_cost(last_result.tokens_used, current_model),
            done=True,
            status="completed" if last_result.success else "failed",
        )

    # Still running
    return ResultResponse(
        step=orchestrator.step_count if orchestrator else 0,
        total=0,
        duration=duration,
        total_tokens=orchestrator.llm.token_count if orchestrator else 0,
        total_cost=0.0,
        done=False,
        status="running",
    )


@app.post("/stop")
async def stop_task() -> ModelResponse:
    """Terminate the current task."""
    global task_running
    task_running = False
    return ModelResponse(status="ok")


# ── Helpers ──────────────────────────────────────────────────────────

async def _run_task(prompt: str, target_url: str):
    """Execute the orchestrator and store the result."""
    global last_result, task_running, orchestrator

    if orchestrator is None:
        task_running = False
        return

    try:
        result = await orchestrator.run(
            task_description=prompt,
            target_url=target_url,
        )
        last_result = result
    except Exception as e:
        last_result = TaskResult(
            success=False, error=str(e),
            time_elapsed=time.time() - task_start_time,
        )
    finally:
        task_running = False


def _extract_target_url(prompt: str) -> str:
    """Extract target URL from PACEBench prompt.

    PACEBench prompts typically contain a URL like:
    "The target is at http://localhost:8080"
    or just directly include the URL.
    """
    import re
    # Match URLs in the prompt
    urls = re.findall(r"https?://[^\s\"'<>]+", prompt)
    if urls:
        return urls[0].rstrip(".,;:'\"")
    raise ValueError("Could not extract target URL from prompt")


def _estimate_cost(tokens: int, model: str) -> float:
    """Estimate API cost based on token count and model."""
    # Approximate costs per 1K tokens (as of 2025-2026)
    costs_per_1k = {
        "gpt-4o": 0.005,
        "gpt-5": 0.015,
        "gpt-5-mini": 0.003,
        "claude-sonnet-4": 0.003,
        "claude-opus-4": 0.015,
        "deepseek-v3": 0.001,
        "gemini-2.5-flash": 0.001,
    }
    rate = costs_per_1k.get(model, 0.005)
    return (tokens / 1000) * rate


def main():
    """Start the PACEBench adapter server."""
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
