import argparse
import json
from pathlib import Path
from .main import process_sample


def validate_file(path, name):
    if not path.exists():
        print(f"{name} file does not exist")
        return False

    if not path.is_file():
        print(f"{name} path is not a file")
        return False

    return True


def validate_sample_path(path):
    if not path.exists():
        print("Sample path does not exist")
        return False

    if not path.is_file() and not path.is_dir():
        print("Sample path is not a file or directory")
        return False

    return True


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("rule")
    parser.add_argument("sample")
    parser.add_argument("decryptor")
    parser.add_argument(
        "--output",
        default="output",
        help="Directory where extraction results are saved"
    )

    args = parser.parse_args()

    rule = Path(args.rule)
    sample = Path(args.sample)
    decryptor = Path(args.decryptor)
    output_dir = Path(args.output)

    if not validate_file(rule, "Rule"):
        return

    if not validate_sample_path(sample):
        return

    if not validate_file(decryptor, "Decryptor"):
        return

    # ---------------------------------------------------------
    # Single sample
    # ---------------------------------------------------------
    if sample.is_file():

        try:
            result = process_sample(rule, sample, decryptor)
        except Exception as e:
            print(f"[ERROR] {e}")
            return

        print(f"\nExtraction status: {result['status']}")
        print("Extraction result:")
        print(result["config"])

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save result using the sample name
        output_file = output_dir / f"{sample.stem}_config.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print(f"\nSaved extraction to: {output_file}")

    # ---------------------------------------------------------
    # Sample directory
    # ---------------------------------------------------------
    elif sample.is_dir():

        all_results = []

        for sample_file in sample.iterdir():
            if not sample_file.is_file():
                continue

            print(f"\n{'=' * 60}")
            print(f"Processing: {sample_file.name}")
            print(f"{'=' * 60}")

            try:
                result = process_sample(rule, sample_file, decryptor)
            except Exception as e:
                print(f"[ERROR] {sample_file.name}: {e}")
                continue

            print(f"\nExtraction status: {result['status']}")
            print("Extraction result:")
            print(result["config"])

            all_results.append({
                "sample": sample_file.name,
                "result": result
            })

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # One combined JSON file for the directory
        output_file = output_dir / f"{rule.stem}.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=4)

        print(f"\nSaved combined extraction to: {output_file}")


if __name__ == "__main__":
    main()