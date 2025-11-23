#!/bin/sh
CURRENTDIR=$(pwd)
# File containing the list of items (one per line)
INPUT_FILE="search.txt"

# Check if the input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Input file not found: $INPUT_FILE"
    exit 1
fi
docker pull ghcr.io/gitleaks/gitleaks:latest
# Read each line from the input file and call process_line.sh
while IFS= read -r line; do
    # Call process_line.sh with the line as an argument
    export REPO_NAME=$line
	./script.sh -r "$line" -u https://hub.docker.com/
	./scan.sh
	cd $CURRENTDIR
	docker run -v $CURRENTDIR"/archives-image/":/path   ghcr.io/gitleaks/gitleaks:latest detect  -e GIT_DISCOVERY_ACROSS_FILESYSTEM=1 -v -s "/path" -f json -r /path/gitleaks.json
	cd $CURRENTDIR
	docker run -v  /$CURRENTDIR"/archives-image/":/path trufflesecurity/trufflehog:latest filesystem /path -j  >> trufflehog.json
	rm -rf $CURRENTDIR/archives-imag*
done < "$INPUT_FILE"

cd $CURRENTDIR
python3 parser.py
rm -rf $CURRENTDIR/archives-imag*

