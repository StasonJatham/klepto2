#!/bin/sh
set -eu

image=${1:-klepto2:local}
container=$(docker create "$image" --mode image docker.io/library/hello-world:latest)
workdir=$(mktemp -d)
trap 'docker rm -f "$container" >/dev/null; rm -rf "$workdir"' EXIT

docker start -a "$container"
test "$(docker inspect --format '{{.State.ExitCode}}' "$container")" = 0
docker cp "$container:/app/output/." "$workdir/"
python3 - "$workdir/results_docker.io_library_hello-world_latest.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as report_file:
    report = json.load(report_file)

assert report["image"] == "docker.io/library/hello-world:latest", report
assert report["image_metadata"]["LayersCount"] > 0, report
for key in ("file_findings", "trufflehog_findings", "gitleaks_findings"):
    assert isinstance(report[key], list), key
PY

docker run --rm -i --entrypoint python "$image" - <<'PY'
from pathlib import Path
from tempfile import TemporaryDirectory

from klepto2 import FileScanner

with TemporaryDirectory() as directory:
    root = Path(directory)
    for name in (
        "root/.codex/auth.json",
        "home/user/.aws/sso/cache/session.json",
        ".kube/config",
        "unrelated/auth.json",
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic value")
    (root / ".kube/config").unlink()
    (root / ".kube/config").symlink_to(root / "unrelated/auth.json")

    findings = FileScanner().scan(directory, "fixture")
    assert len(findings) == 2, findings
    assert any("Found CODEX AUTH:" in finding for finding in findings), findings
    assert any("Found AWS SSO CACHE:" in finding for finding in findings), findings
    assert all("synthetic value" not in finding for finding in findings), findings
PY
