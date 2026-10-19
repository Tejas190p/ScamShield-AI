from app import analyze_message, calculate_risk
from category_engine import detect_category
from category_signals import detect_category_signals
from risk_engine import merge_risk_signals, get_risk_level

# Loaded from external dataset
import json
from pathlib import Path

DATASET_PATH = Path(__file__).parent / "eval_dataset.json"
with open(DATASET_PATH, "r", encoding="utf-8") as f:
    TEST_CASES = json.load(f)


def main():
    category_passed = 0
    risk_passed = 0
    tp = fp = fn = tn = 0

    print("\nSCAMSHIELD AI â€” CATEGORY AND RISK EVALUATION")
    print("=" * 72)

    for case in TEST_CASES:
        analysis = analyze_message(case["message"])
        actual_category = detect_category(case["message"], analysis)
        score, _, reasons = calculate_risk(analysis)

        category_signals = detect_category_signals(
            case["message"],
            actual_category,
        )

        score, reasons = merge_risk_signals(
            base_score=score,
            base_reasons=reasons,
            category_signals=category_signals,
        )
        actual_risk = get_risk_level(score)

        actual_scam = case["ground_truth"] == "SCAM"
        predicted_scam = actual_risk in ("HIGH", "MEDIUM")

        if predicted_scam and actual_scam:
            tp += 1
        elif predicted_scam and not actual_scam:
            fp += 1
        elif not predicted_scam and actual_scam:
            fn += 1
        else:
            tn += 1

        category_ok = actual_category == case["expected_category"]
        risk_ok = actual_risk == case["expected_risk"]

        category_passed += category_ok
        risk_passed += risk_ok

        print(f"\n{case['name']}")
        print(
            f"  Category: {'PASS' if category_ok else 'FAIL'}"
            f" | expected={case['expected_category']}"
            f" | actual={actual_category}"
        )
        print(
            f"  Risk:     {'PASS' if risk_ok else 'FAIL'}"
            f" | expected={case['expected_risk']}"
            f" | actual={actual_risk} | score={score}"
        )

        if reasons:
            print(f"  Reasons: {', '.join(map(str, reasons))}")

    total = len(TEST_CASES)
    print("\n" + "=" * 72)
    print(f"Category matches: {category_passed}/{total}")
    print(f"Risk matches:     {risk_passed}/{total}")
    print(f"Combined checks:  {category_passed + risk_passed}/{total * 2}")

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    print("\nSCAM DETECTION METRICS")
    print("-" * 72)
    print(f"True positives:  {tp}")
    print(f"False positives: {fp}")
    print(f"False negatives: {fn}")
    print(f"True negatives:  {tn}")
    print(f"Precision:       {precision:.2%}")
    print(f"Recall:          {recall:.2%}")
    print(f"F1 score:        {f1:.2%}")

if __name__ == "__main__":
    main()

