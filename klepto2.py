import argparse
import os
import subprocess
import json
import logging
import requests
import tempfile
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

__version__ = "2.0.0"


class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored logs."""

    FORMATS = {
        logging.DEBUG: Fore.CYAN
        + "%(asctime)s - %(levelname)s - %(message)s"
        + Style.RESET_ALL,
        logging.INFO: Fore.GREEN
        + "%(asctime)s - %(levelname)s - %(message)s"
        + Style.RESET_ALL,
        logging.WARNING: Fore.YELLOW
        + "%(asctime)s - %(levelname)s - %(message)s"
        + Style.RESET_ALL,
        logging.ERROR: Fore.RED
        + "%(asctime)s - %(levelname)s - %(message)s"
        + Style.RESET_ALL,
        logging.CRITICAL: Fore.RED
        + Style.BRIGHT
        + "%(asctime)s - %(levelname)s - %(message)s"
        + Style.RESET_ALL,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


# Configure logging
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = (
    False  # Prevent duplicate logs if root logger is configured elsewhere
)


class Config:
    """Configuration for the scanner."""

    DESIRED_DETECTOR_TYPES = [
        2,
        3,
        7,
        9,
        15,
        17,
        18,
        31,
        39,
        40,
        48,
        69,
        71,
        120,
        177,
        350,
        353,
        582,
        584,
        599,
        737,
        924,
    ]
    UNDESIRED_TERMS = ["example", "test", "dummy", "sample"]
    MAX_WORKERS = 4
    OUTPUT_DIR = "/app/output"

    SENSITIVE_FILES = [
        {"name": "SHADOW", "pattern": "shadow", "action": "shadow"},
        {"name": "SSH KEY", "pattern": "*id_[rd]sa", "action": "exist"},
        {"name": "GIT CONFIG", "pattern": ".git/config", "action": "cat"},
        {"name": "HTPASSWD", "pattern": ".htpasswd", "action": "cat"},
        {"name": "NPMRC", "pattern": ".npmrc", "action": "cat"},
        {"name": "DOCKERCFG", "pattern": ".dockercfg", "action": "cat"},
        {"name": "PPK", "pattern": "*.ppk", "action": "cat"},
        {"name": ".CREDENTIALS", "pattern": ".credentials", "action": "cat"},
        {"name": "CREDENTIALS (AWS)", "pattern": "credentials", "action": "cat"},
        {"name": ".S3CFG", "pattern": ".s3cfg", "action": "cat"},
        {"name": "WP-CONFIG.PHP", "pattern": "wp-config.php", "action": "cat"},
        {"name": ".ENV", "pattern": ".env", "action": "cat"},
        {"name": ".GIT-CREDENTIALS", "pattern": ".git-credentials", "action": "cat"},
        {"name": ".BASH_HISTORY", "pattern": ".bash_history", "action": "cat"},
        {"name": ".NETRC", "pattern": ".netrc", "action": "cat"},
        {"name": "FILEZILLA.XML", "pattern": "filezilla.xml", "action": "cat"},
        {"name": "RECENTSERVERS.XML", "pattern": "recentservers.xml", "action": "cat"},
        {"name": "CONFIG.JSON", "pattern": "config.json", "action": "cat"},
        {"name": ".PGPASS", "pattern": ".pgpass", "action": "cat"},
        # Flag credential stores without copying their contents into the report.
        {"name": "AWS CONFIG", "pattern": ".aws/config", "action": "exist"},
        {
            "name": "AWS SSO CACHE",
            "pattern": ".aws/sso/cache/*.json",
            "action": "exist",
        },
        {
            "name": "GOOGLE ADC",
            "pattern": "application_default_credentials.json",
            "action": "exist",
        },
        {
            "name": "GCLOUD CREDENTIALS",
            "pattern": "gcloud/credentials.db",
            "action": "exist",
        },
        {
            "name": "AZURE TOKEN CACHE",
            "pattern": ".azure/msal_token_cache.*",
            "action": "exist",
        },
        {"name": "KUBECONFIG", "pattern": ".kube/config", "action": "exist"},
        {
            "name": "TERRAFORM CREDENTIALS",
            "pattern": "credentials.tfrc.json",
            "action": "exist",
        },
        {"name": "CODEX AUTH", "pattern": ".codex/auth.json", "action": "exist"},
        {
            "name": "CLAUDE CODE CREDENTIALS",
            "pattern": ".claude/.credentials.json",
            "action": "exist",
        },
        {
            "name": "HUGGING FACE TOKEN",
            "pattern": "huggingface/token",
            "action": "exist",
        },
        {"name": "WANDB SETTINGS", "pattern": "wandb/settings", "action": "exist"},
    ]


class HubClient:
    """Interacts with Docker Hub API."""

    BASE_URL = "https://hub.docker.com/v2"

    def search(self, term: str) -> List[str]:
        """Search for repositories on Docker Hub."""
        url = f"{self.BASE_URL}/search/repositories/"
        params = {"query": term, "page_size": 100}
        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            return [repo["repo_name"] for repo in data.get("results", [])]
        except Exception as e:
            logger.error(f"Docker Hub search failed: {e}")
            return []

    def get_best_tag(self, repo_name: str) -> Optional[str]:
        """Get the 'latest' tag or the most recent tag for a repo."""
        if "/" not in repo_name:
            repo_name = f"library/{repo_name}"

        url = f"{self.BASE_URL}/repositories/{repo_name}/tags"
        try:
            response = requests.get(url, params={"page_size": 10}, timeout=30)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()
            results = data.get("results", [])

            if not results:
                return None

            # Prefer 'latest'
            for tag in results:
                if tag["name"] == "latest":
                    return "latest"

            # Otherwise return the first one (most recent usually)
            return results[0]["name"]
        except Exception as e:
            logger.warning(f"Failed to get tags for {repo_name}: {e}")
            return None


class SkopeoClient:
    """Handles image operations using Skopeo."""

    @staticmethod
    def inspect_image(image_name: str) -> Optional[dict]:
        """Inspects the image using skopeo inspect."""
        cmd = [
            "skopeo",
            "inspect",
            "--override-os",
            "linux",
            "--retry-times",
            "3",
            f"docker://{image_name}",
        ]
        try:
            result = subprocess.run(
                cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to inspect {image_name}: {e.stderr.decode()}")
            return None
        except json.JSONDecodeError:
            logger.error(f"Failed to parse inspect output for {image_name}")
            return None

    @staticmethod
    def pull_image(image_name: str, dest_path: str) -> bool:
        """
        Pull image using skopeo to a directory.
        skopeo copy docker://<image> dir:<path>
        """
        logger.info(f"Downloading {image_name}...")

        cmd = [
            "skopeo",
            "copy",
            "--override-os",
            "linux",  # Ensure we get linux images
            "--retry-times",
            "3",  # Retry on failure
            f"docker://{image_name}",
            f"dir:{dest_path}",
        ]
        try:
            subprocess.run(
                cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            logger.info(f"Download complete for {image_name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to pull {image_name}: {e.stderr.decode()}")
            return False


class FileScanner:
    """Scans directories for sensitive files based on patterns."""

    def __init__(self):
        self.findings = []

    def add_finding(self, message: str, console: bool = False, level: str = "INFO"):
        """Add a finding to the list and optionally log to console."""
        self.findings.append(message)

        if console:
            if level == "WARNING":
                logger.warning(f"{Fore.MAGENTA}[FINDING]{Style.RESET_ALL} {message}")
            else:
                logger.info(message)

    def scan(self, directory: str, repo_name: str) -> List[str]:
        for check in Config.SENSITIVE_FILES:
            title = check["name"]
            pattern = check["pattern"]
            action_type = check["action"]

            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    candidate = (
                        os.path.relpath(filepath, directory)
                        if "/" in pattern
                        else filename
                    )
                    if not self._match_pattern(candidate, pattern):
                        continue
                    if os.path.islink(filepath) or not os.path.isfile(filepath):
                        continue
                    if action_type == "shadow":
                        self._check_shadow(filepath)
                    elif action_type == "cat":
                        if pattern == ".git/config":
                            self.add_finding(
                                f"Found GIT CONFIG: {root}",
                                console=True,
                                level="WARNING",
                            )
                        self._cat_file(filepath)
                    else:
                        self.add_finding(
                            f"Found {title}: {filepath}", console=True, level="WARNING"
                        )
        return self.findings

    def _match_pattern(self, filename: str, pattern: str) -> bool:
        import fnmatch

        filename, pattern = filename.lower(), pattern.lower()
        return fnmatch.fnmatchcase(filename, pattern) or (
            "/" in pattern and fnmatch.fnmatchcase(filename, f"*/{pattern}")
        )

    def _check_shadow(self, filepath: str):
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
                if "$" in content:
                    self.add_finding(
                        f"Found SHADOW file: {filepath}", console=True, level="WARNING"
                    )
                    for line in content.splitlines():
                        if "$" in line:
                            self.add_finding(
                                f"Shadow content: {line}", console=True, level="WARNING"
                            )
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")

    def _cat_file(self, filepath: str):
        self.add_finding(
            f"Found sensitive file: {filepath}", console=True, level="WARNING"
        )
        try:
            with open(filepath, "r", errors="ignore") as f:
                self.add_finding(f"Content of {filepath}:\n{f.read()}")
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")


class Klepto2:
    def __init__(self):
        self.hub_client = HubClient()
        self.skopeo_client = SkopeoClient()

        # Setup output directory
        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)

    def extract_image(self, image_dir: str, extract_root: str):
        logger.info(f"Extracting layers from {image_dir} to {extract_root}")
        os.makedirs(extract_root, exist_ok=True)

        with open(os.path.join(image_dir, "manifest.json")) as manifest_file:
            layers = json.load(manifest_file)["layers"]

        for layer in layers:
            digest = layer["digest"]
            if (
                not digest
                or os.path.basename(digest) != digest
                or digest in (".", "..")
            ):
                raise ValueError(f"Invalid layer digest: {digest!r}")
            filepath = os.path.join(image_dir, digest.removeprefix("sha256:"))
            if not os.path.isfile(filepath):
                filepath = os.path.join(image_dir, digest)
            subprocess.run(["tar", "-xf", filepath, "-C", extract_root], check=True)

    def run_trufflehog(self, directory: str, output_file: str):
        with open(output_file, "w") as outfile:
            subprocess.run(
                ["trufflehog", "filesystem", directory, "--json", "--no-update"],
                stdout=outfile,
                check=True,
            )

    def run_gitleaks(self, directory: str, output_file: str):
        subprocess.run(
            [
                "gitleaks",
                "dir",
                directory,
                "--exit-code",
                "0",
                "--report-format",
                "json",
                "--report-path",
                output_file,
            ],
            stdout=subprocess.DEVNULL,
            check=True,
        )

    def parse_trufflehog_results(self, input_file: str) -> List[dict]:
        if not os.path.exists(input_file):
            return []

        all_data = []
        with open(input_file, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        all_data.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        filtered_data = []
        for obj in all_data:
            raw = obj.get("Raw", "")
            detector_type = obj.get("DetectorType")

            if detector_type in Config.DESIRED_DETECTOR_TYPES:
                if raw and any(term in raw.lower() for term in Config.UNDESIRED_TERMS):
                    continue

                filtered_data.append(
                    {
                        "SourceMetadata": obj.get("SourceMetadata"),
                        "DetectorName": obj.get("DetectorName"),
                        "DetectorType": detector_type,
                        "Raw": raw,
                    }
                )
        return filtered_data

    def process_image(self, image_name: str) -> Optional[str]:
        # Resolve tag if missing
        if ":" not in image_name:
            # Check if it's a custom registry
            is_custom_registry = (
                len(image_name.split("/")) > 1 and "." in image_name.split("/")[0]
            )

            if is_custom_registry:
                image_name += ":latest"
            else:
                tag = self.hub_client.get_best_tag(image_name)
                if tag:
                    image_name = f"{image_name}:{tag}"
                else:
                    image_name += ":latest"

        logger.info(f"Processing {image_name}...")

        # Inspect image metadata
        metadata = self.skopeo_client.inspect_image(image_name)
        image_info = {}
        if metadata:
            created = metadata.get("Created", "Unknown")
            architecture = metadata.get("Architecture", "Unknown")
            os_name = metadata.get("Os", "Unknown")
            layers_count = len(metadata.get("Layers", []))
            env_vars = metadata.get("Env", [])

            image_info = {
                "Created": created,
                "Architecture": architecture,
                "Os": os_name,
                "LayersCount": layers_count,
                "Env": env_vars,
                "Labels": metadata.get("Labels", {}),
            }

            logger.info(
                f"Image Metadata: Created={created}, Arch={architecture}, OS={os_name}, Layers={layers_count}"
            )
            if env_vars:
                logger.info(f"Found {len(env_vars)} environment variables.")

        safe_name = image_name.replace("/", "_").replace(":", "_")

        # Use a temporary directory for the entire process of this image
        with tempfile.TemporaryDirectory() as temp_dir:
            image_dir = os.path.join(temp_dir, "image_data")
            os.makedirs(image_dir, exist_ok=True)

            extract_dir = os.path.join(temp_dir, "extracted")

            if not self.skopeo_client.pull_image(image_name, image_dir):
                return None

            self.extract_image(image_dir, extract_dir)

            # 1. File Pattern Scan
            file_scanner = FileScanner()
            file_findings = file_scanner.scan(extract_dir, image_name)

            # 2. TruffleHog Scan
            th_output_tmp = os.path.join(temp_dir, "trufflehog.json")
            self.run_trufflehog(extract_dir, th_output_tmp)
            trufflehog_findings = self.parse_trufflehog_results(th_output_tmp)

            # 3. Gitleaks Scan
            gl_output_tmp = os.path.join(temp_dir, "gitleaks.json")
            self.run_gitleaks(extract_dir, gl_output_tmp)

            gitleaks_findings = []
            if os.path.exists(gl_output_tmp):
                with open(gl_output_tmp) as f:
                    gitleaks_findings = json.load(f) or []

            # Combine all results
            final_result = {
                "image": image_name,
                "scan_timestamp": os.popen("date -u +%Y-%m-%dT%H:%M:%SZ")
                .read()
                .strip(),
                "image_metadata": image_info,
                "file_findings": file_findings,
                "trufflehog_findings": trufflehog_findings,
                "gitleaks_findings": gitleaks_findings,
            }

            output_file = os.path.join(Config.OUTPUT_DIR, f"results_{safe_name}.json")
            with open(output_file, "w") as f:
                json.dump(final_result, f, indent=4)

            logger.info(
                f"Scan complete for {image_name}. Results saved to {output_file}"
            )
            return output_file

    def run(self, inputs: List[str], mode: str):
        image_names = []

        if mode == "search":
            for term in inputs:
                logger.info(f"Searching for: {term}")
                found = self.hub_client.search(term)
                logger.info(f"Found {len(found)} images for '{term}'")
                image_names.extend(found)
        elif mode == "image":
            image_names = inputs
        elif mode == "mixed":
            for term in inputs:
                # Detect if input is a specific image or a search term
                # It's an image if:
                # 1. It has a tag (contains ':') e.g. "ubuntu:latest"
                # 2. It comes from a registry (domain contains '.') e.g. "quay.io/coreos/etcd"
                is_image = ":" in term or (
                    len(term.split("/")) > 1 and "." in term.split("/")[0]
                )

                if is_image:
                    logger.info(f"Adding specific image: {term}")
                    image_names.append(term)
                else:
                    logger.info(f"Searching for: {term}")
                    found = self.hub_client.search(term)
                    logger.info(f"Found {len(found)} images for '{term}'")
                    image_names.extend(found)

        # Remove duplicates
        image_names = list(set(image_names))

        logger.info(
            f"Identified {len(image_names)} unique images to scan: {image_names}"
        )

        if not image_names:
            logger.info("No images to process.")
            return False

        logger.info(
            f"Starting scan of {len(image_names)} images with {Config.MAX_WORKERS} workers."
        )

        success = True
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            future_to_image = {
                executor.submit(self.process_image, img): img for img in image_names
            }
            for future in as_completed(future_to_image):
                image_name = future_to_image[future]
                try:
                    if future.result() is None:
                        success = False
                except Exception as exc:
                    success = False
                    logger.error(f"{image_name} generated an exception: {exc}")

        logger.info("All scans completed. Exiting.")
        return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Klepto2: Scan Docker images for secrets."
    )

    # Input arguments
    parser.add_argument("inputs", nargs="*", help="Search terms or image names")
    parser.add_argument(
        "--file", "-f", help="File containing list of terms or images (one per line)"
    )
    parser.add_argument(
        "--mode",
        choices=["search", "image", "mixed"],
        default="mixed",
        help="Mode: 'search' for terms, 'image' for direct image names, 'mixed' (default) detects based on format (contains ':')",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version and exit",
    )

    # Configuration
    parser.add_argument(
        "--workers",
        type=int,
        default=Config.MAX_WORKERS,
        help="Number of concurrent workers",
    )
    parser.add_argument("--output", default=Config.OUTPUT_DIR, help="Output directory")
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress console output (only JSON output)",
    )

    args = parser.parse_args()

    if args.quiet:
        logger.setLevel(logging.CRITICAL)

    Config.MAX_WORKERS = args.workers
    Config.OUTPUT_DIR = args.output

    # Collect inputs
    target_inputs = args.inputs
    if args.file:
        if os.path.exists(args.file):
            with open(args.file, "r") as f:
                target_inputs.extend([line.strip() for line in f if line.strip()])
        else:
            logger.error(f"Input file not found: {args.file}")
            exit(1)

    if not target_inputs:
        logger.error("No inputs provided. Use arguments or --file.")
        exit(1)

    klepto = Klepto2()
    raise SystemExit(0 if klepto.run(target_inputs, args.mode) else 1)
