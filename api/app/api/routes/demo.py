from fastapi import APIRouter

from app.services.dataset_loader import load_demo_scenarios

router = APIRouter()


@router.get("/samples")
def demo_samples() -> dict:
    return {"samples": load_demo_scenarios()}


@router.get("/walkthrough")
def walkthrough() -> dict:
    return {
        "steps": [
            {
                "title": "Paste prompt",
                "description": "Enter a multilingual prompt in Live Shield and run combined mode.",
            },
            {
                "title": "Inspect detections",
                "description": "Review confidence-scored entities and sanitized prompt output.",
            },
            {
                "title": "Run conversation",
                "description": "Observe deterministic placeholders preserved across turns.",
            },
            {
                "title": "Attack in lab",
                "description": "Execute adversarial suite and verify leakage resistance.",
            },
            {
                "title": "Review audit",
                "description": "Filter event logs and export secure CSV evidence.",
            },
        ]
    }
