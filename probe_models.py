import json
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "src")
from sentinel.llm_client import config_from_env

cfg = config_from_env()
prompt = json.load(open("rca_output/7-6/correlation_prompt.json", encoding="utf-8"))
user_text = json.dumps(prompt, ensure_ascii=False)

for model in (
    "mistralai/mistral-large-2-instruct",
    "z-ai/glm-5.3-flash",
    "minimaxai/minimax-m3.1-flash",
    "deepseek-ai/deepseek-v4.1-flash",
    "ai21labs/jamba-1.5-large-instruct",
):
    body = {
        "model": model,
        "temperature": 0,
        "max_tokens": 8000,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "You return strictly valid JSON. No markdown, no commentary."},
            {"role": "user", "content": user_text},
        ],
    }
    req = urllib.request.Request(
        f"{cfg['base_url']}/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"},
        method="POST",
    )
    start = time.time()
    print(f"\n=== {model} ===")
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            payload = json.loads(resp.read().decode())
        elapsed = time.time() - start
        msg = payload["choices"][0]["message"]
        content = msg.get("content") or ""
        usage = payload.get("usage", {})
        print(f"done in {elapsed:.1f}s | usage: {usage.get('prompt_tokens')} in / {usage.get('completion_tokens')} out | content: {len(content)} chars")
        try:
            parsed = json.loads(content)
            print("VALID JSON -> edges:", len(parsed.get("edges", [])),
                  "| chain:", len(parsed.get("attack_chain", [])),
                  "| threat:", (parsed.get("threat") or {}).get("threat_level"))
        except json.JSONDecodeError:
            print("NOT JSON:", content[:150])
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code} after {time.time()-start:.1f}s: {exc.read().decode()[:200]}")
    except Exception as exc:
        print(f"{type(exc).__name__} after {time.time()-start:.1f}s: {exc}")
