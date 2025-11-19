#!/bin/sh
CURRENTDIR=$(pwd)
# File containing the list of items (one per line)
INPUT_FILE="search.txt"

# Check if the input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Input file not found: $INPUT_FILE"
    exit 1
fi

# Read each line from the input file and call process_line.sh
while IFS= read -r line; do
    # Call process_line.sh with the line as an argument
    ./script.sh -r "$line" -u https://hub.docker.com/
    export REPO_NAME=$line
done < "$INPUT_FILE"

cd $CURRENTDIR

docker pull ghcr.io/gitleaks/gitleaks:latest
docker run -v $CURRENTDIR"/archives-image/":/path   ghcr.io/gitleaks/gitleaks:latest detect  -v -s "/path" -f json -r /path/gitleaks.json
cd $CURRENTDIR
docker run -v  /$CURRENTDIR"/archives-image/":/path trufflesecurity/trufflehog:latest filesystem /path -j  > trufflehog.json
cd $CURRENTDIR
python3 parser.py