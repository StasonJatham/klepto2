#!/bin/sh
CURRENTDIR=$(pwd)
# File containing the list of items (one per line)
INPUT_FILE="search.txt"
export GIT_DISCOVERY_ACROSS_FILESYSTEM=1

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
	REPO_NAME_STR=`echo $REPO_NAME | awk -F\/ '{ print $1"_"$2}'`
	echo $REPO_NAME_STR
	docker run -v  $CURRENTDIR"/archives-image/":/path trufflesecurity/trufflehog:latest filesystem /path -j > "trufflehog_"$REPO_NAME_STR".json"
	docker run -v $CURRENTDIR"/archives-image/":/path ghcr.io/gitleaks/gitleaks:latest detect --no-git -v -s "/path" -f json -r "/path/gitleaks"$REPO_NAME_STR".json"
	cp $CURRENTDIR"/archives-image/gitleaks"$REPO_NAME_STR".json" $CURRENTDIR/"gitleaks"$REPO_NAME_STR".json"
	rm -rf $CURRENTDIR"/archives-image/"
	rm -rf $CURRENTDIR"/archives-image-tar/"
done < "$INPUT_FILE"
cd $CURRENTDIR
cat trufflehog_* > trufflehog.json
python3 parser.py

