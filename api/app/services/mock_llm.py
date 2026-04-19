import re
import logging

import httpx

from app.core.config import get_settings
from app.services.detector import output_guard
from app.services.normalization import collapse_whitespace

logger = logging.getLogger(__name__)

QUESTION_HINTS = (
    "what",
    "why",
    "how",
    "when",
    "where",
    "who",
    "can",
    "could",
    "should",
)

STOPWORDS = {
    "the",
    "and",
    "with",
    "from",
    "this",
    "that",
    "your",
    "please",
    "about",
    "into",
    "show",
    "tell",
    "give",
    "make",
    "mera",
    "meri",
    "mere",
    "kya",
    "hai",
    "ka",
    "ki",
    "ke",
}


def _topic_from_prompt(prompt: str) -> str:
    cleaned = re.sub(r"\[[A-Z_0-9]+\]", "entity", prompt)
    words = re.findall(r"[A-Za-z]{3,}", cleaned.lower())
    keywords = [word for word in words if word not in STOPWORDS]
    if not keywords:
        return "your request"
    return " ".join(keywords[:4])


def _is_question(prompt: str) -> bool:
    lower = prompt.lower()
    if "?" in prompt:
        return True
    return any(lower.startswith(f"{hint} ") for hint in QUESTION_HINTS)


def _is_greeting(prompt: str) -> bool:
    lower = prompt.lower()
    return any(token in lower for token in ("hello", "hi", "assalam", "salam", "hey"))


def simulate_model_response(sanitized_prompt: str) -> str:
    prompt = collapse_whitespace(sanitized_prompt)
    lower = prompt.lower()
    topic = _topic_from_prompt(prompt)

    if _is_greeting(prompt):
        return (
            "Hello. I am ready to help. "
            "Share your question and I will respond while keeping sensitive data masked."
        )

    if "[FINANCIAL_" in prompt or "[NATIONAL_ID_" in prompt:
        return (
            "I can help with your request while protecting confidential data. "
            "Sensitive identifiers were replaced with stable placeholders for privacy-safe processing. "
            "If you want, I can explain each step without exposing private values."
        )

    if "health" in lower or "doctor" in lower:
        return (
            "For health-related guidance, consult a licensed professional. "
            "I can summarize your next steps without exposing personal records."
        )

    if "summarize" in lower or "summary" in lower:
        return (
            f"Summary: your request is about {topic}. "
            "I can provide a short overview, key points, and practical next actions."
        )

    if "explain" in lower or "difference" in lower:
        return (
            f"Here is a simple explanation related to {topic}: "
            "first define the concept, then compare core parts, then apply an example."
        )

    if _is_question(prompt):
        return (
            f"Good question about {topic}. "
            "Based on your message, I suggest starting with a concise answer, then examples, then a quick checklist."
        )

    return (
        f"I received your message about {topic}. "
        "I can help you draft, summarize, or analyze it while PromptShield keeps sensitive data protected."
    )


def _extract_gemini_text(payload: dict) -> str:
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return ""

    first = candidates[0]
    content = first.get("content") if isinstance(first, dict) else None
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list):
        return ""

    chunks: list[str] = []
    for part in parts:
        if isinstance(part, dict):
            text = part.get("text")
            if isinstance(text, str):
                chunks.append(text)
    return collapse_whitespace(" ".join(chunks))


def _gemini_response(sanitized_prompt: str) -> str | None:
    settings = get_settings()
    api_key = settings.GEMINI_API_KEY.strip()
    if not api_key:
        return None

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.GEMINI_MODEL}:generateContent"
    payload = {
        "system_instruction": {
            "parts": [
                {
                    "text": (
                        "You are PromptShield assistant. Answer clearly and briefly. "
                        "Do not attempt to recover hidden sensitive values. "
                        "Treat placeholders as opaque references."
                    )
                }
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": sanitized_prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.35,
            "maxOutputTokens": 512,
        },
    }

    try:
        with httpx.Client(timeout=settings.LLM_TIMEOUT_SECONDS) as client:
            response = client.post(url, params={"key": api_key}, json=payload)
            if response.status_code >= 400:
                logger.warning("Gemini request failed with status %s", response.status_code)
                return None
            text = _extract_gemini_text(response.json())
            return text or None
    except Exception as exc:  # pragma: no cover - network path
        logger.warning("Gemini request failed: %s", exc)
        return None


def generate_assistant_response(sanitized_prompt: str) -> str:
    settings = get_settings()
    provider = settings.LLM_PROVIDER.strip().lower()

    if provider in {"gemini", "google", "google_gemini"}:
        external = _gemini_response(sanitized_prompt)
        if external:
            return external

    return simulate_model_response(sanitized_prompt)


def guard_model_output(output_text: str) -> tuple[str, bool, float]:
    guarded = output_guard(output_text, strict=True)
    return guarded.sanitized_text, guarded.blocked, guarded.risk_score
