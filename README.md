# Klepto2

Klepto2 scans container images for embedded secrets and sensitive files. It
downloads image layers with Skopeo and scans the extracted files with
TruffleHog, Gitleaks, and filename and path rules. The container runs as a
non-root user and does not need access to the host Docker socket.

## Build and scan an image

From the repository root, with Docker running:

```sh
docker build -t klepto2:local .
mkdir -p results
docker run --rm --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD/results,target=/app/output" \
  klepto2:local --mode image docker.io/library/hello-world:latest
```

The example writes `results/results_docker.io_library_hello-world_latest.json`.
Use `--mode image` for known image references, including images from other
registries. To search Docker Hub, replace the arguments after the image name
with `--mode search SEARCH_TERM`. Search can return multiple images, which are
scanned concurrently. The default `mixed` mode treats tagged references and
registry-qualified names as images and searches Docker Hub for other inputs.

| Option | Purpose |
| --- | --- |
| `--mode {image,search,mixed}` | Choose how to interpret inputs. Defaults to `mixed`. |
| `--file PATH` | Read additional inputs, one per line. Mount the file into the container when using Docker. |
| `--workers N` | Number of concurrent image scans. Defaults to 4. |
| `--output DIR` | Output directory inside the container. Defaults to `/app/output`. |
| `--quiet` | Suppress application logs. |

## Reports and coverage

Each image produces a JSON report containing image metadata and separate
findings for file rules, TruffleHog, and Gitleaks. A path match flags a file for
review; it does not establish that the file contains a live credential.

File rules cover common targets such as `.env`, SSH keys, and Git credentials.
Additional rules flag AWS, Google Cloud, Azure, Kubernetes, Terraform, Codex,
Claude Code, Hugging Face, and W&B configuration or credential stores. These
additional rules report paths only. Scanner findings, legacy file rules, and
image metadata can still include secrets; keep reports private.

Layers are extracted into a shared directory. A later layer can overwrite a
file from an earlier one, so a clean report does not establish that every
historical layer is free of secrets.

## Test

```sh
sh tests/smoke.sh klepto2:local
```

The smoke test pulls Docker Hub's `hello-world` example, runs both scanners,
checks the JSON report, and checks the new path rules with synthetic files.
CI runs the same test after building the image.

## License and credits

Klepto2 is licensed under [GPL-3.0](LICENSE.txt). It builds on
[Telekom Security's Klepto](https://github.com/telekom-security/klepto),
originally developed by Maximilian Gutowski and Jakub Sucharkiewicz. Karl
Machleidt adapted the project into Klepto2.
