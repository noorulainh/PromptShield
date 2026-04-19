import argparse
import json

from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.services.adversarial import run_adversarial_suite
from app.services.evaluation import run_evaluation_suite
from app.services.seed import seed_default_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PromptShield evaluation suite")
    parser.add_argument("--include-adversarial", action="store_true", help="Run adversarial suite alongside evaluation")
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        seed_default_settings(db)
        eval_summary = run_evaluation_suite(db)
        output = {"evaluation": eval_summary}

        if args.include_adversarial:
            output["adversarial"] = run_adversarial_suite(db, mode="ml_based")

    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
