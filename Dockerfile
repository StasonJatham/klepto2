FROM golang:1.27.3-trixie AS skopeo
RUN CGO_ENABLED=0 go install -tags 'exclude_graphdriver_btrfs containers_image_openpgp' go.podman.io/skopeo/cmd/skopeo@v1.24.1

FROM trufflesecurity/trufflehog:3.99.8 AS trufflehog
FROM ghcr.io/gitleaks/gitleaks:v8.30.1 AS gitleaks

FROM python:3.15.2-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends tar zstd \
    && rm -rf /var/lib/apt/lists/*
# Match the previous distro setup: allow unsigned registry images over TLS.
RUN mkdir -p /etc/containers && printf '%s\n' \
    '{"default":[{"type":"reject"}],"transports":{"docker":{"":[{"type":"insecureAcceptAnything"}]}}}' \
    > /etc/containers/policy.json
COPY --from=skopeo /go/bin/skopeo /usr/local/bin/skopeo
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY klepto2.py .
RUN useradd -m klepto && mkdir /app/output && chown klepto:klepto /app/output
USER klepto

ENTRYPOINT ["python", "klepto2.py"]
