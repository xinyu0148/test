import argparse
import csv
import json
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "output" / "evaluation"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
    return rows


def local_decision(score: float) -> str:
    if score < 3.0:
        return "local_safe"
    if score <= 6.5:
        return "needs_server"
    return "local_phishing"


def correctness(actual_label: str, decision: str) -> str:
    if decision == "needs_server":
        return "escalated_phishing" if actual_label == "phishing" else "escalated_legit"
    if decision == "local_safe":
        return "true_safe" if actual_label == "legit" else "false_safe"
    if decision == "local_phishing":
        return "true_phishing" if actual_label == "phishing" else "false_phishing"
    return "unknown"


def normalize_result(row: dict[str, Any]) -> dict[str, Any]:
    score = row.get("score", row.get("risk_score"))
    if score is None:
        raise ValueError(f"Result row missing score/risk_score for id={row.get('id')}")
    return {
        "id": row["id"],
        "score": float(score),
        "level": row.get("level", row.get("risk_level", "")),
        "verdict": row.get("verdict", ""),
        "confidence": row.get("confidence", ""),
        "reasoning": row.get("reasoning", ""),
        "indicators": row.get("indicators", []),
        "latency_ms": row.get("latency_ms", row.get("processingTimeMs", "")),
    }


def merge(dataset: list[dict[str, Any]], results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result_by_id = {row["id"]: normalize_result(row) for row in results}
    merged = []
    missing = []
    for sample in dataset:
        result = result_by_id.get(sample["id"])
        if result is None:
            missing.append(sample["id"])
            continue
        decision = local_decision(result["score"])
        merged.append({
            "id": sample["id"],
            "source_group": sample["source_group"],
            "source_file": sample["source_file"],
            "row_number": sample["row_number"],
            "actual_label": sample["actual_label"],
            "score": result["score"],
            "level": result["level"],
            "verdict": result["verdict"],
            "confidence": result["confidence"],
            "local_decision": decision,
            "correctness": correctness(sample["actual_label"], decision),
            "latency_ms": result["latency_ms"],
            "indicators": json.dumps(result["indicators"], ensure_ascii=False),
            "reasoning": result["reasoning"],
            "analysis_text": sample["analysis_text"],
        })
    if missing:
        print(f"Warning: {len(missing)} dataset samples have no result. First missing id: {missing[0]}")
    return merged


def count_by(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field, ""))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    decisions = count_by(rows, "local_decision")
    correctness_counts = count_by(rows, "correctness")
    by_actual_label = count_by(rows, "actual_label")
    by_source_group = count_by(rows, "source_group")

    non_escalated = [r for r in rows if r["local_decision"] != "needs_server"]
    local_correct = sum(1 for r in non_escalated if r["correctness"] in {"true_safe", "true_phishing"})
    local_accuracy = local_correct / len(non_escalated) if non_escalated else None

    return {
        "total_scored": total,
        "decision_counts": decisions,
        "correctness_counts": correctness_counts,
        "actual_label_counts": by_actual_label,
        "source_group_counts": by_source_group,
        "non_escalated_count": len(non_escalated),
        "non_escalated_local_accuracy": local_accuracy,
        "escalation_rate": decisions.get("needs_server", 0) / total if total else None,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "id",
        "source_group",
        "source_file",
        "row_number",
        "actual_label",
        "score",
        "level",
        "verdict",
        "confidence",
        "local_decision",
        "correctness",
        "latency_ms",
        "indicators",
        "reasoning",
        "analysis_text",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_summary_md(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# PhishGuard Local Text Evaluation Summary",
        "",
        f"Total scored samples: {summary['total_scored']}",
        f"Escalation rate: {summary['escalation_rate']:.4f}" if summary["escalation_rate"] is not None else "Escalation rate: n/a",
        f"Non-escalated local accuracy: {summary['non_escalated_local_accuracy']:.4f}" if summary["non_escalated_local_accuracy"] is not None else "Non-escalated local accuracy: n/a",
        "",
        "## Decision Counts",
    ]
    for key, value in summary["decision_counts"].items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Correctness Counts")
    for key, value in summary["correctness_counts"].items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Actual Label Counts")
    for key, value in summary["actual_label_counts"].items():
        lines.append(f"- {key}: {value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate PhishGuard app local SLM results.")
    parser.add_argument("--dataset", required=True, type=Path, help="Prepared dataset JSONL")
    parser.add_argument("--results", required=True, type=Path, help="App-generated local result JSONL")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    dataset = read_jsonl(args.dataset)
    results = read_jsonl(args.results)
    rows = merge(dataset, results)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "evaluated_samples.csv", rows)
    write_csv(args.output_dir / "needs_server.csv", [r for r in rows if r["local_decision"] == "needs_server"])
    write_csv(args.output_dir / "local_safe.csv", [r for r in rows if r["local_decision"] == "local_safe"])
    write_csv(args.output_dir / "local_phishing.csv", [r for r in rows if r["local_decision"] == "local_phishing"])

    summary = build_summary(rows)
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_summary_md(args.output_dir / "summary.md", summary)

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"Output directory: {args.output_dir}")


if __name__ == "__main__":
    main()
