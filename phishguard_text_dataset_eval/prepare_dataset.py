import argparse
import csv
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path


DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "output"


def clean_text(value: str) -> str:
    value = (value or "").replace("\r\n", "\n").replace("\r", "\n")
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def stable_id(source_file: str, row_number: int, text: str) -> str:
    digest = hashlib.sha1(f"{source_file}:{row_number}:{text[:200]}".encode("utf-8")).hexdigest()
    return f"sample_{digest[:12]}"


def split_from_path(path: str) -> tuple[str, str]:
    parts = path.replace("\\", "/").split("/")
    source_group = parts[0] if parts else "unknown"
    file_name = parts[-1].lower()
    if "legit" in file_name:
        label = "legit"
    elif "phishing" in file_name:
        label = "phishing"
    else:
        label = "unknown"
    return source_group, label


def iter_human_rows(source_file: str, data: str):
    reader = csv.DictReader(io.StringIO(data))
    for row_number, row in enumerate(reader, start=1):
        text = clean_text(row.get("body", ""))
        if not text:
            continue
        yield {
            "row_number": row_number,
            "text": text,
            "original_csv_label": row.get("label", ""),
            "subject": clean_text(row.get("subject", "")),
            "sender": clean_text(row.get("sender", "")),
            "receiver": clean_text(row.get("receiver", "")),
            "urls": clean_text(row.get("urls", "")),
        }


def iter_llm_rows(source_file: str, data: str):
    reader = csv.reader(io.StringIO(data))
    header = next(reader, None)
    _ = header
    for row_number, row in enumerate(reader, start=1):
        if not row:
            continue

        # Some LLM CSV rows contain unquoted commas, so join every column except
        # the last label-like field back into the text body.
        original_label = row[-1].strip() if len(row) > 1 else ""
        text_columns = row[:-1] if len(row) > 1 else row
        text = clean_text(",".join(text_columns))
        if not text:
            continue
        yield {
            "row_number": row_number,
            "text": text,
            "original_csv_label": original_label,
            "subject": "",
            "sender": "",
            "receiver": "",
            "urls": "",
        }


def load_samples(zip_path: Path) -> list[dict]:
    samples = []
    with zipfile.ZipFile(zip_path) as archive:
        for source_file in archive.namelist():
            if not source_file.lower().endswith(".csv"):
                continue
            source_group, actual_label = split_from_path(source_file)
            data = archive.read(source_file).decode("utf-8-sig", errors="replace")
            iterator = iter_human_rows(source_file, data)
            if source_group.lower().startswith("llm"):
                iterator = iter_llm_rows(source_file, data)

            for item in iterator:
                sample = {
                    "id": stable_id(source_file, item["row_number"], item["text"]),
                    "source_group": source_group,
                    "source_file": source_file,
                    "row_number": item["row_number"],
                    "actual_label": actual_label,
                    "actual_is_phishing": actual_label == "phishing",
                    "analysis_text": item["text"],
                    "original_csv_label": item["original_csv_label"],
                    "subject": item["subject"],
                    "sender": item["sender"],
                    "receiver": item["receiver"],
                    "urls": item["urls"],
                }
                samples.append(sample)
    return samples


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "id",
        "source_group",
        "source_file",
        "row_number",
        "actual_label",
        "actual_is_phishing",
        "original_csv_label",
        "subject",
        "sender",
        "receiver",
        "urls",
        "analysis_text",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def summary(samples: list[dict]) -> dict:
    result: dict[str, int | dict[str, int]] = {"total": len(samples), "by_split": {}}
    by_split: dict[str, int] = {}
    for sample in samples:
        key = f"{sample['source_group']}/{sample['actual_label']}"
        by_split[key] = by_split.get(key, 0) + 1
    result["by_split"] = dict(sorted(by_split.items()))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare PhishGuard text-only dataset.")
    parser.add_argument("--zip", required=True, type=Path, help="Path to archive.zip")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    samples = load_samples(args.zip)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    jsonl_path = args.output_dir / "phishguard_text_dataset.jsonl"
    csv_path = args.output_dir / "phishguard_text_dataset.csv"
    summary_path = args.output_dir / "dataset_summary.json"

    write_jsonl(jsonl_path, samples)
    write_csv(csv_path, samples)
    summary_data = summary(samples)
    summary_path.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Wrote {len(samples)} samples")
    print(f"JSONL: {jsonl_path}")
    print(f"CSV:   {csv_path}")
    print(f"Summary: {summary_path}")
    print(json.dumps(summary_data, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
