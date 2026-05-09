import argparse
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE_DIR = ROOT / "Sources" / "PhishGuardSLMBatch"
ASSET_DIR = ROOT / "assets" / "SLM"


def safe_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def extract_slm(zip_path: Path) -> None:
    if not zip_path.exists():
        raise FileNotFoundError(zip_path)

    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)

    model_dir = ASSET_DIR / "PhishingDetector.mlpackage"
    if model_dir.exists():
        shutil.rmtree(model_dir)

    with zipfile.ZipFile(zip_path) as archive:
        for name in archive.namelist():
            if name.startswith("__MACOSX/") or name.endswith(".DS_Store") or "/._" in name:
                continue

            if name in {
                "SLM/PhishingDetectorRunner.swift",
                "SLM/OnDevicePhishingAnalyzer.swift",
            }:
                target = SOURCE_DIR / Path(name).name
                safe_write(target, archive.read(name))
                print(f"Extracted source: {target}")
                continue

            if name == "SLM/tokenizer.json":
                target = ASSET_DIR / "tokenizer.json"
                safe_write(target, archive.read(name))
                print(f"Extracted tokenizer: {target}")
                continue

            prefix = "SLM/PhishingDetector.mlpackage/"
            if name.startswith(prefix):
                relative = name[len(prefix):]
                if not relative:
                    continue
                target = model_dir / relative
                if name.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    safe_write(target, archive.read(name))
                    print(f"Extracted model file: {target}")

    required = [
        SOURCE_DIR / "PhishingDetectorRunner.swift",
        SOURCE_DIR / "OnDevicePhishingAnalyzer.swift",
        ASSET_DIR / "tokenizer.json",
        model_dir / "Manifest.json",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise RuntimeError("Missing extracted files:\n" + "\n".join(missing))


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract SLM files into standalone Swift batch runner.")
    parser.add_argument("--zip", required=True, type=Path, help="Path to PhishGuard-SLM-T6-CoreML zip")
    args = parser.parse_args()

    extract_slm(args.zip)
    print("\nSLM-only runner is ready.")
    print(f"Project: {ROOT}")
    print(f"Model:   {ASSET_DIR / 'PhishingDetector.mlpackage'}")
    print(f"Tokenizer: {ASSET_DIR / 'tokenizer.json'}")


if __name__ == "__main__":
    main()
