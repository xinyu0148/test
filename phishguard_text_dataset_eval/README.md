# PhishGuard Text Dataset Evaluation

This folder is a standalone evaluation helper. It does not modify the PhishGuard app.

## Goal

Use the dataset emails as plain text input only. The original dataset split is preserved:

- `human-generated/legit.csv`
- `human-generated/phishing.csv`
- `llm-generated/legit.csv`
- `llm-generated/phishing.csv`

The app-side analysis should use the local on-device layer only. Server escalation is not executed during this test. Instead, samples whose local score falls into the escalation range are marked and separated.

## Decision Rules

These rules mirror the current app decision threshold:

- `score < 3.0`: `local_safe`
- `3.0 <= score <= 6.5`: `needs_server`
- `score > 6.5`: `local_phishing`

`needs_server` samples are separated from local final decisions.

## Files

- `prepare_dataset.py`: reads `archive.zip`, extracts only the body/text content, and creates normalized JSONL/CSV files.
- `evaluate_app_results.py`: merges app SLM results with the dataset labels and separates results by decision type.
- `swift/PhishGuardDatasetBatchRunner.swift`: optional Swift helper to run inside the PhishGuard app or test target on macOS/Xcode with the real SLM model available.

## Workflow

1. Prepare the text-only dataset:

```powershell
python .\phishguard_text_dataset_eval\prepare_dataset.py --zip "C:\Users\73125\Downloads\archive.zip"
```

2. Copy `output/phishguard_text_dataset.jsonl` into the Xcode project or test bundle.

3. Run the Swift helper with the real app SLM available. It should produce `phishguard_local_results.jsonl`.

4. Evaluate and split the results:

```powershell
python .\phishguard_text_dataset_eval\evaluate_app_results.py `
  --dataset .\phishguard_text_dataset_eval\output\phishguard_text_dataset.jsonl `
  --results path\to\phishguard_local_results.jsonl
```

## Output Meaning

The evaluator writes:

- `evaluated_samples.csv`: all scored samples with label, score, level, and local decision.
- `needs_server.csv`: samples that should be escalated to server.
- `local_safe.csv`: samples locally treated as safe.
- `local_phishing.csv`: samples locally treated as phishing.
- `summary.json`: machine-readable summary.
- `summary.md`: human-readable summary.

For non-escalated samples, correctness is marked as:

- `true_safe`: actual legit and local decision is safe.
- `false_safe`: actual phishing but local decision is safe.
- `true_phishing`: actual phishing and local decision is phishing.
- `false_phishing`: actual legit but local decision is phishing.
- `escalated_legit`: actual legit and sent to server.
- `escalated_phishing`: actual phishing and sent to server.
