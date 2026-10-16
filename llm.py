
"""
Fast shared Gemini helper for the security pipeline.

- Makes one API request per ask() call.
- No application-level retry loop.
- Uses a request timeout and disables SDK retries.
- Supports JSON responses.
- Keeps the existing ask() and parse_json() interfaces.

Requirements:
    pip install -U google-genai

Environment variables:
    GEMINI_API_KEY (or GOOGLE_API_KEY)
    GEMINI_MODEL (optional)
"""

import json
import os
import re

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
TIMEOUT_MS = int(os.environ.get("GEMINI_TIMEOUT_MS", "8000"))

_client = None


def client():
    """Create the Gemini client only when it is first needed."""
    global _client

    if _client is None:
        api_key = (
            os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
        )

        if not api_key:
            raise RuntimeError(
                "Gemini API key missing. Set GEMINI_API_KEY "
                "or GOOGLE_API_KEY."
            )

        from google import genai
        from google.genai import types

        _client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                timeout=TIMEOUT_MS,
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )

    return _client


def ask(prompt, want_json=False, retries=0):
    """
    Send one request to Gemini.

    The retries parameter is retained for compatibility with existing
    code, but this function intentionally does not retry failed requests.

    Raises an exception on API failure so the caller can use a fallback.
    """
    from google.genai import types

    config_options = {
        "max_output_tokens": 1200,
        "temperature": 0.1,
        "automatic_continuation": False,
    }

    if want_json:
        config_options["response_mime_type"] = "application/json"

    config = types.GenerateContentConfig(**config_options)

    try:
        response = client().models.generate_content(
            model=MODEL,
            contents=prompt,
            config=config,
        )

        text = response.text

        if not text or not text.strip():
            raise RuntimeError("Gemini returned an empty response.")

        return text.strip()

    except Exception as exc:
        # Fail fast. Do not sleep and retry during the demo.
        raise RuntimeError(
            f"Gemini request failed ({type(exc).__name__}): {exc}"
        ) from exc


def parse_json(text):
    """Parse JSON from a model reply, tolerating code fences."""
    text = (text or "").strip()

    match = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if match:
        text = match.group(1).strip()

    try:
        return json.loads(text)
    except ValueError:
        pass

    # Try extracting a JSON object or array from surrounding text.
    for open_char, close_char in (("{", "}"), ("[", "]")):
        start = text.find(open_char)
        end = text.rfind(close_char)

        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except ValueError:
                continue

    raise ValueError("Model did not return valid JSON.")
