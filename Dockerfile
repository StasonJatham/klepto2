FROM docker:25.0.5-cli

# Install runtime dependencies used by the shell scripts and parser
RUN apk add --no-cache \
    bash \
    coreutils \
    curl \
    jq \
    python3

WORKDIR /app
COPY . /app

# Make sure helper scripts are executable
RUN chmod +x search.sh search_scan.sh scan.sh script.sh parser.sh || true

ENV PYTHONUNBUFFERED=1

# Default entrypoint runs the search workflow; override with --entrypoint for other scripts
ENTRYPOINT ["./search.sh"]
