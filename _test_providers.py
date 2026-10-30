"""Temporary connectivity check for each configured LLM provider (deleted after use)."""
import json
import sys
import urllib.request

sys.path.insert(0, "src")
from sentinel.llm_client import config_from_env  # noqa: E402

chain = config_from_env()
if not chain:
    print("NO LLM CONFIGURED (no provider/key found)")
    sys.exit(1)

ok = True
for i, cfg in enumerate(chain):
    label = f"[{i + 1}/{len(chain)}] {cfg['provider']} / {cfg['model']}"
    print(f"\n=== {label} ===")
    request = urllib.request.Request(
        f"{cfg['base_url']}/chat/completions",
        data=json.dumps({
            "model": cfg["model"],
            "temperature": 0,
            "max_tokens": 200,
            "messages": [
                {"role": "user",
                 "content": "Reply in one short sentence: are you working right now, and which model are you?"},
            ],
        }).encode("utf-8"),
        headers={"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = (payload.get("choices") or [{}])[0].get("message", {}).get("content")
        print("RESPONSE:", content)
    except urllib.error.HTTPError as exc:
        ok = False
        print(f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:300]}")
    except Exception as exc:
        ok = False
        print("ERROR:", exc)

print("\n" + ("ALL PROVIDERS OK" if ok else "SOME PROVIDERS FAILED"))
