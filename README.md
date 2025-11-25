<div align="center">
  <img src="docs/image.png" alt="Klepto2 Logo" width="200" />
  <h1>Klepto2</h1>
  <p><strong>Advanced Docker Image Secrets Scanner</strong></p>
  <p>
    <a href="#features">Features</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#output">Output</a> •
    <a href="#contributing">Contributing</a>
  </p>
</div>

---

## 📖 About

**Klepto2** is a powerful security tool designed to search for and scan Docker images for embedded secrets. It automates the process of pulling images, extracting their layers, and running industry-standard secret scanning tools like **TruffleHog** and **Gitleaks**. Additionally, it performs custom pattern matching to identify sensitive files such as shadow files, SSH keys, and configuration files.

### Why Skopeo?

Unlike many other tools, Klepto2 uses **Skopeo** to pull images. This is a critical security feature because it removes the requirement for access to the host Docker socket (`/var/run/docker.sock`).

* **No Privileged Access**: Runs safely in restricted environments (CI/CD, Kubernetes) without root privileges.
* **Isolation**: The image is downloaded and extracted within the container's temporary storage, ensuring no pollution of the host's Docker daemon.
* **Security**: Eliminates the risk of container breakout attacks associated with mounting the Docker socket.

## ✨ Features

* **🔍 Search Docker Hub**: Automatically find and scan images matching specific search terms.
* **🌐 Multi-Registry Support**: Scan images from any public registry (e.g., Quay, GCR, GHCR).
* **🎯 Direct Image Scan**: Target specific images by name and tag.
* **🔐 Deep Secret Scanning**: Integrates **TruffleHog** and **Gitleaks** for comprehensive secret detection.
* **📂 File Pattern Matching**: Detects sensitive files (e.g., `.env`, `id_rsa`, `.htpasswd`, `config.json`).
* **⚡ Concurrent Scanning**: Multi-threaded processing for high-performance scanning of multiple images.
* **🛡️ Secure Execution**: Uses `skopeo` to pull images without requiring privileged Docker socket access.

## 🚀 Installation

Klepto2 is containerized for ease of use. Simply build the Docker image:

```bash
docker build -t klepto2 .
```

## 💻 Usage

Klepto2 outputs all results to `/app/output` inside the container. To access these results on your host machine, mount a volume to this path.

### 1. Search and Scan

Search for images on Docker Hub matching a term and scan them immediately.

```bash
docker run --rm -v $(pwd)/results:/app/output klepto2 "search_term"
```

### 2. Scan Specific Images

Scan a list of known images directly.

```bash
docker run --rm -v $(pwd)/results:/app/output klepto2 --mode image "ubuntu:latest" "nginx:alpine"
```

### 3. Scan from Other Registries

Klepto2 supports scanning public images from any registry (Quay, GCR, GHCR, etc.).

```bash
docker run --rm -v $(pwd)/results:/app/output klepto2 "quay.io/prometheus/node-exporter"
```

### 4. Scan from File

Provide a list of search terms or image names in a text file (one per line). Klepto2's default `mixed` mode will automatically detect if a line is a specific image (contains `:`) or a search term.

```bash
# Create a targets file
echo "nginx" > targets.txt          # Will search for 'nginx' images
echo "ubuntu:latest" >> targets.txt # Will scan specific 'ubuntu:latest' image

# Run scan
docker run --rm -v $(pwd)/results:/app/output -v $(pwd)/targets.txt:/targets.txt klepto2 --file /targets.txt
```

### ⚙️ Options

| Option | Description | Default |
|--------|-------------|---------|
| `inputs` | List of search terms or image names | N/A |
| `--mode` | Operation mode: `search`, `image`, or `mixed` | `mixed` |
| `--file` | Path to a file containing inputs | `None` |
| `--workers` | Number of concurrent workers | `4` |
| `--output` | Internal output directory | `/app/output` |

## 📊 Output

The tool generates a single, consolidated JSON report for each scanned image in your output directory:

* `results_<image_name>.json`: A comprehensive report containing:
  * **File Findings**: Sensitive files detected via pattern matching (e.g., `.env`, `id_rsa`, `config.json`).
  * **TruffleHog Findings**: Secrets and credentials detected by TruffleHog.
  * **Gitleaks Findings**: Secrets and keys detected by Gitleaks.

Each report includes a timestamp and details for every finding.

## 🤝 Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve Klepto2.

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 📜 License

This project is licensed under the **GPL 3.0** License.

## 👥 Authors & Acknowledgements

This tool is a fork and evolution of the original **Klepto** project.

* **Original Authors**: [Maximilian Gutowski](https://github.com/m-gutowski) and [Jakub Sucharkiewicz](https://github.com/jsucharkiewicz) from [Telekom Security](https://github.com/telekom-security).
* **Original Repository**: [https://github.com/telekom-security/klepto](https://github.com/telekom-security/klepto)

**Klepto2** has been heavily re-written and modernized by **Karl Machleidt** to include a robust Python architecture, multi-stage builds, and enhanced security features.

The Klepto2 logo is based on the original project's assets.

---
<div align="center">
  <sub>Built with ❤️ by the Open Source Community</sub>
</div>