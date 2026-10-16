import time
from google import genai

c = genai.Client(http_options={"timeout": 30000})
for m in ["models/gemini-flash-latest", "models/gemini-2.5-flash-lite", "models/gemini-3.8-flash"]:
    t = time.time()
    try:
        r = c.models.generate_content(model=m, contents="Reply with only: ok")
        print(m, "->", (r.text or "").strip()[:20], f"{time.time() - t:.1f}s", flush=True)
    except Exception as e:
        print(m, "-> ERROR", str(e)[:100], f"{time.time() - t:.1f}s", flush=True)