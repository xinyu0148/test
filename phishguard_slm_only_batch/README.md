# PhishGuard SLM-Only Batch Test

This is a standalone macOS Swift runner for testing the SLM package without the PhishGuard app.

It uses only:

- `PhishingDetectorRunner.swift`
- `OnDevicePhishingAnalyzer.swift`
- `PhishingDetector.mlpackage`
- `tokenizer.json`

The runner adds only minimal support types that normally come from the app, such as `RiskLevel`, `ModalityType`, and `AnalyzeResponse`.

## What This Test Does

For each prepared dataset sample, it sends only `analysis_text` to the local SLM and records:

- local score
- risk level
- verdict
- confidence
- reasoning
- indicators
- local decision

It does not call the app decision engine and does not call any server API.

## Decision Rule

The output uses the same escalation threshold:

```text
score < 3.0         local_safe
3.0 <= score <= 6.5 needs_server
score > 6.5         local_phishing
```

`needs_server` is only a label in this batch test. No network request is sent.

## Setup

Run this once to extract the SLM files from the zip into this standalone runner:

```powershell
python .\phishguard_slm_only_batch\extract_slm_zip.py --zip "C:\Users\73125\Downloads\PhishGuard-SLM-T6-CoreML(1.0).zip"
```

This creates:

```text
phishguard_slm_only_batch/assets/SLM/PhishingDetector.mlpackage
phishguard_slm_only_batch/assets/SLM/tokenizer.json
phishguard_slm_only_batch/Sources/PhishGuardSLMBatch/PhishingDetectorRunner.swift
phishguard_slm_only_batch/Sources/PhishGuardSLMBatch/OnDevicePhishingAnalyzer.swift
```

## Run On Mac

This must be run on macOS because CoreML is required.

From Terminal:

```bash
cd /path/to/phishguard_slm_only_batch

swift run -c release PhishGuardSLMBatch \
  --dataset ../phishguard_text_dataset_eval/output/phishguard_text_dataset.jsonl \
  --model assets/SLM/PhishingDetector.mlpackage \
  --tokenizer assets/SLM/tokenizer.json \
  --output output/phishguard_local_results.jsonl
```

For a quick smoke test:

```bash
swift run PhishGuardSLMBatch \
  --dataset ../phishguard_text_dataset_eval/output/phishguard_text_dataset.jsonl \
  --model assets/SLM/PhishingDetector.mlpackage \
  --tokenizer assets/SLM/tokenizer.json \
  --output output/phishguard_local_results.jsonl \
  --limit 20
```

## Evaluate Results

After `phishguard_local_results.jsonl` is generated, run:

```bash
python ../phishguard_text_dataset_eval/evaluate_app_results.py \
  --dataset ../phishguard_text_dataset_eval/output/phishguard_text_dataset.jsonl \
  --results output/phishguard_local_results.jsonl
```

The evaluator will create:

- `needs_server.csv`
- `local_safe.csv`
- `local_phishing.csv`
- `evaluated_samples.csv`
- `summary.json`
- `summary.md`

