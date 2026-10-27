import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(
        description="Compile and test the Poseidon1 policy experiments through a Go overlay."
    )
    parser.add_argument("--run", default="^Test(Forest|Outlined)", help="Go test name filter")
    parser.add_argument("--output", type=Path, required=True, help="Result directory")
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    prover = source.parents[1] / "prover"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    replacements = {
        str(prover / "circuits/policy" / path.name): str(path)
        for path in sorted(source.glob("*_test.go"))
    }
    environment = dict(os.environ, FOREST_RESULTS_DIR=str(output))
    with tempfile.TemporaryDirectory(prefix="policy-constraints-") as temporary:
        overlay = Path(temporary) / "overlay.json"
        overlay.write_text(json.dumps({"Replace": replacements}))
        command = [
            "go", "test", "-overlay", str(overlay), "./circuits/policy",
            "-run", args.run, "-count=1", "-v",
        ]
        with (output / "tests.log").open("w") as log:
            result = subprocess.run(
                command, cwd=prover, env=environment, stdout=log, stderr=subprocess.STDOUT
            )
    print(output / "tests.log")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
