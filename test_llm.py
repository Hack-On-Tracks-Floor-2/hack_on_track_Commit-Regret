import os
from fixloop import ask_json, MODEL, FALLBACKS

print("gemini key set:", bool(os.environ.get("GEMINI_API_KEY")))
print("model:", MODEL)
print("fallbacks:", FALLBACKS)
print(ask_json('Reply with only this JSON: {"ok": true}'))