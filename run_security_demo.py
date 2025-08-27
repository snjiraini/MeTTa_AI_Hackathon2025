#!/usr/bin/env python3
import os
import json
import time
import uuid
import argparse
from typing import Dict, Any, List

import requests

# Security layer (must be in same dir or PYTHONPATH)
import metta_llm_security as sec

# Strictly require curated 100 prompts from test_prompt_injection.py
try:
    import test_prompt_injection as tpi
except Exception as e:
    raise RuntimeError("Failed to import test_prompt_injection.py. Ensure it is present alongside this script.") from e

if not hasattr(tpi, "FAILED_ATTACKS") or not isinstance(tpi.FAILED_ATTACKS, list):
    raise RuntimeError("test_prompt_injection.FAILED_ATTACKS missing or not a list.")
if len(tpi.FAILED_ATTACKS) != 100:
    raise RuntimeError(f"Expected 100 tailored prompts, got {len(tpi.FAILED_ATTACKS)}.")

FAILED_ATTACKS: List[str] = tpi.FAILED_ATTACKS

def chat_completion(
    base_url: str,
    api_key: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: float,
    max_tokens: int,
    timeout: int,
) -> Dict[str, Any]:
    url = f"{base_url}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
        "messages": messages,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()

def run_demo(
    prompts: List[str],
    base_url: str,
    api_key: str,
    model: str,
    temperature: float,
    max_tokens: int,
    timeout: int,
    out_path: str,
    run_id: str,
) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        for i, user_prompt in enumerate(prompts):
            t0 = time.time()
            prompt_guard = sec.guard_prompt(user_prompt)
            prompt_action = prompt_guard.get("action", "allow")
            message_override = prompt_guard.get("message_override", "")
            record: Dict[str, Any] = {
                "run_id": run_id,
                "seq": i,
                "timestamp": time.time(),
                "model": model,
                "prompt": user_prompt,
                "prompt_guard": prompt_guard,
                "prompt_action": prompt_action,
            }

            if prompt_action == "block":
                record.update({
                    "response": "",
                    "response_guard": {"severity": prompt_guard.get("severity"), "reason": "blocked at prompt"},
                    "final_text": message_override or "I can’t assist with that request.",
                    "latency_sec": time.time() - t0,
                })
            else:
                try:
                    api_json = chat_completion(
                        base_url=base_url,
                        api_key=api_key,
                        model=model,
                        messages=[{"role": "user", "content": user_prompt}],
                        temperature=temperature,
                        max_tokens=max_tokens,
                        timeout=timeout,
                    )
                    raw_text = api_json["choices"][0]["message"]["content"]
                    response_guard = sec.guard_response(raw_text)
                    final_text = response_guard.get("text", raw_text)
                    record.update({
                        "api_json": api_json,
                        "response": raw_text,
                        "response_guard": response_guard,
                        "final_text": final_text,
                        "latency_sec": time.time() - t0,
                    })
                except Exception as e:
                    record.update({
                        "error": str(e),
                        "latency_sec": time.time() - t0,
                    })

            f.write(json.dumps(record) + "\n")
            print(f"[{i+1:03}/100] action={prompt_action} ok")

    print(f"Wrote 100 results to {out_path}")

def main():
    parser = argparse.ArgumentParser(description="Run MeTTa security-wrapped tailored 100 attacks against Ollama (OpenAI-compatible API).")
    parser.add_argument("--model", default=os.getenv("MODEL", "dolphin-llama3"))
    parser.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL", "http://localhost:11434/v1"))
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", "ollama"))
    parser.add_argument("--temperature", type=float, default=float(os.getenv("TEMP", "0.2")))
    parser.add_argument("--max-tokens", type=int, default=int(os.getenv("MAX_TOKENS", "512")))
    parser.add_argument("--timeout", type=int, default=int(os.getenv("TIMEOUT", "60")))
    parser.add_argument("--out", default=f"security_demo_{uuid.uuid4().hex}.jsonl")
    args = parser.parse_args()

    run_id = uuid.uuid4().hex

    print(f"Running 100 tailored prompts with MeTTa security guardrails.")
    print(f"Model: {args.model}  Base URL: {args.base_url}  Out: {args.out}")

    run_demo(
        prompts=FAILED_ATTACKS,
        base_url=args.base_url,
        api_key=args.api_key,
        model=args.model,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        timeout=args.timeout,
        out_path=args.out,
        run_id=run_id,
    )

if __name__ == "__main__":
    main()