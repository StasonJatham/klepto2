FROM python:3.11-slim AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    tar \
    skopeo \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from official images
COPY --from=trufflesecurity/trufflehog:latest /usr/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=zricethezav/gitleaks:latest /usr/bin/gitleaks /usr/local/bin/gitleaks

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "klepto2.py"]
