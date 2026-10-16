import os
from fixloop import ask_json

print("provider:", os.environ.get("LLM_PROVIDER"))
print("model:", os.environ.get("GROQ_MODEL"))
print("key set:", bool(os.environ.get("GROQ_API_KEY")))

out = ask_json('Reply with only this JSON: {"ok": true}')
print("reply:", repr(out))