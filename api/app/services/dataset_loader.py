import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT_DIR / "data"


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_demo_scenarios() -> list[dict]:
    return _load_json(DATA_DIR / "demo_samples.json")


def load_adversarial_cases() -> list[dict]:
    return _load_json(DATA_DIR / "adversarial" / "cases.json")


def load_entity_eval_cases() -> list[dict]:
    return _load_json(DATA_DIR / "evaluation" / "entity_cases.json")


def load_conversation_eval_cases() -> list[dict]:
    return _load_json(DATA_DIR / "evaluation" / "conversation_cases.json")


def load_security_training_data() -> list[dict]:
    return _load_json(DATA_DIR / "training" / "security_multilingual.json")
