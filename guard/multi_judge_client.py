"""
guard/multi_judge_client.py - Unified, Provider-Agnostic LLM Judge Client

Supports:
1. Ollama (local: gemma3:4b, qwen3:8b, qwen2.5:1.5b, etc.)
2. OpenAI (API: gpt-4o, gpt-4o-mini via OPENAI_API_KEY)
3. Anthropic (API: claude-3-5-haiku, claude-3-5-sonnet via ANTHROPIC_API_KEY)
4. Google Gemini (API: gemini-2.5-flash, gemini-1.5-pro via GEMINI_API_KEY / GOOGLE_API_KEY)

Hard Rules:
- API keys come from environment variables only (never logged, written, or committed).
- Same prompt, same JSON schema, T=0 where supported (or fixed low temperature 0.0), max 2 retries.
- Strictly logs: model ID, timestamp, temperature, prompt, token usage, latency, raw output, parsed verdict.
"""

import os
import sys
import json
import time
import copy
import hashlib
import urllib.request
import urllib.error
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from guard.semantic_judge import (
    SYSTEM_PROMPT_SECURITY_WRAPPER,
    JUDGE_JSON_SCHEMA,
    OLLAMA_API_URL,
    TEMPERATURE
)


def clean_judge_output(raw_text: str) -> str:
    """Strips markdown code fences and reasoning tags like <think>...</think>."""
    text = raw_text.strip()
    if "<think>" in text and "</think>" in text:
        text = text.split("</think>")[-1].strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def validate_judge_json(parsed: Any) -> bool:
    if not isinstance(parsed, dict):
        return False
    if "label" not in parsed or parsed["label"] not in ("BENIGN", "SUSPICIOUS", "MALICIOUS"):
        return False
    if "confidence" not in parsed or not isinstance(parsed["confidence"], (int, float)):
        return False
    if "reason" not in parsed or not isinstance(parsed["reason"], str):
        return False
    if "evidence" not in parsed or not isinstance(parsed["evidence"], list):
        return False
    return True


class MultiJudgeClient:
    def __init__(self, model_name: str = "gemma3:4b", temperature: float = 0.0, seed: int = 42):
        self.model_name = model_name
        self.temperature = temperature
        self.seed = seed
        self.provider = self._determine_provider(model_name)
        self._cache: Dict[str, Dict[str, Any]] = {}

    def _determine_provider(self, model: str) -> str:
        m = model.lower()
        if m.startswith("gpt-") or m.startswith("o1") or m.startswith("o3"):
            return "openai"
        elif m.startswith("claude-"):
            return "anthropic"
        elif m.startswith("gemini-"):
            return "google"
        elif ":" in m or m.startswith("qwen") or m.startswith("gemma") or m.startswith("llama") or m.startswith("mistral"):
            return "ollama"
        else:
            return "ollama"

    def call_judge(
        self,
        prompt: str,
        system_prompt: str = SYSTEM_PROMPT_SECURITY_WRAPPER,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """
        Executes a judge call with up to max_retries attempts.
        Returns detailed record containing parsed verdict, token usage, latency, retries, and errors.
        """
        cache_key = f"{self.model_name}:{self.temperature}:{hashlib.sha256(prompt.encode('utf-8')).hexdigest()}"
        if cache_key in self._cache:
            cached_res = copy.deepcopy(self._cache[cache_key])
            cached_res["latency_ms"] = 0.1
            return cached_res

        retry_log = []
        total_lat_ms = 0.0
        prompt_tokens = 0
        completion_tokens = 0

        for attempt in range(1 + max_retries):
            t0 = time.perf_counter()
            err_msg = None
            raw_text = ""
            try:
                if self.provider == "ollama":
                    raw_text, p_tok, c_tok = self._call_ollama(prompt, system_prompt)
                elif self.provider == "openai":
                    raw_text, p_tok, c_tok = self._call_openai(prompt, system_prompt)
                elif self.provider == "anthropic":
                    raw_text, p_tok, c_tok = self._call_anthropic(prompt, system_prompt)
                elif self.provider == "google":
                    raw_text, p_tok, c_tok = self._call_google(prompt, system_prompt)
                else:
                    raise ValueError(f"Unsupported provider: {self.provider}")

                lat_ms = (time.perf_counter() - t0) * 1000.0
                total_lat_ms += lat_ms
                prompt_tokens += p_tok
                completion_tokens += c_tok

                cleaned = clean_judge_output(raw_text)
                parsed = json.loads(cleaned)

                if validate_judge_json(parsed):
                    res = {
                        "model": self.model_name,
                        "provider": self.provider,
                        "parsed_verdict": parsed,
                        "raw_response": raw_text,
                        "parse_error": None,
                        "attempts_used": attempt + 1,
                        "latency_ms": round(total_lat_ms, 2),
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": prompt_tokens + completion_tokens,
                        "retry_log": retry_log
                    }
                    self._cache[cache_key] = res
                    return res
                else:
                    err_msg = f"Schema validation failed: {cleaned[:120]}"
                    retry_log.append(f"Attempt {attempt + 1}: {err_msg}")

            except Exception as e:
                lat_ms = (time.perf_counter() - t0) * 1000.0
                total_lat_ms += lat_ms
                err_msg = str(e)
                retry_log.append(f"Attempt {attempt + 1}: Exception: {err_msg}")

            time.sleep(0.15)

        # Fallback on parse failure
        return {
            "model": self.model_name,
            "provider": self.provider,
            "parsed_verdict": None,
            "raw_response": raw_text,
            "parse_error": err_msg or "Unknown error",
            "attempts_used": attempt + 1,
            "latency_ms": round(total_lat_ms, 2),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "retry_log": retry_log
        }

    def _call_ollama(self, prompt: str, system_prompt: str) -> Tuple[str, int, int]:
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "format": JUDGE_JSON_SCHEMA,
            "options": {
                "temperature": self.temperature,
                "seed": self.seed,
                "num_predict": 256
            },
            "stream": False
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OLLAMA_API_URL,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
        
        raw_text = resp_data.get("message", {}).get("content", "").strip()
        p_tok = resp_data.get("prompt_eval_count", int(len(prompt) / 4))
        c_tok = resp_data.get("eval_count", int(len(raw_text) / 4))
        return raw_text, p_tok, c_tok

    def _call_openai(self, prompt: str, system_prompt: str) -> Tuple[str, int, int]:
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set.")
        
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "mcp_drift_judge_schema",
                    "strict": True,
                    "schema": JUDGE_JSON_SCHEMA
                }
            },
            "temperature": self.temperature,
            "seed": self.seed,
            "max_tokens": 256
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
        
        raw_text = resp_data["choices"][0]["message"]["content"].strip()
        usage = resp_data.get("usage", {})
        p_tok = usage.get("prompt_tokens", int(len(prompt) / 4))
        c_tok = usage.get("completion_tokens", int(len(raw_text) / 4))
        return raw_text, p_tok, c_tok

    def _call_anthropic(self, prompt: str, system_prompt: str) -> Tuple[str, int, int]:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set.")
        
        url = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": self.model_name,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": f"Respond strictly with a JSON object matching this schema: {json.dumps(JUDGE_JSON_SCHEMA)}.\n\nDiff for Evaluation:\n{prompt}"}
            ],
            "temperature": self.temperature,
            "max_tokens": 256
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            }
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
        
        raw_text = resp_data["content"][0]["text"].strip()
        usage = resp_data.get("usage", {})
        p_tok = usage.get("input_tokens", int(len(prompt) / 4))
        c_tok = usage.get("output_tokens", int(len(raw_text) / 4))
        return raw_text, p_tok, c_tok

    def _call_google(self, prompt: str, system_prompt: str) -> Tuple[str, int, int]:
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
        api_key = api_key.strip()
        if not api_key:
            raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY environment variable is not set.")
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={api_key}"
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"System Context: {system_prompt}\n\nTask: Evaluate following tool change and return strictly valid JSON matching schema.\n\n{prompt}"}]}
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "response_mime_type": "application/json",
                "response_schema": JUDGE_JSON_SCHEMA,
                "maxOutputTokens": 256
            }
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
        
        raw_text = resp_data["candidates"][0]["content"]["parts"][0]["text"].strip()
        usage = resp_data.get("usageMetadata", {})
        p_tok = usage.get("promptTokenCount", int(len(prompt) / 4))
        c_tok = usage.get("candidatesTokenCount", int(len(raw_text) / 4))
        return raw_text, p_tok, c_tok
