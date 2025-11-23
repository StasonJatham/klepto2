#!/bin/sh

# Init
SEARCH_TERM=$1
OUTPUT_FILE="search.txt"
CURRENTDIR=$(pwd)
# Perform the Docker search and extract the image names
image_names=$(docker search "$SEARCH_TERM" --format "{{.Name}}")

# Check if any images were found
if [ -z "$image_names" ]; then
    echo "No images found for search term: $SEARCH_TERM"
    exit 1
fi

# Display the list of image names
echo "List of Docker image names found for '$SEARCH_TERM':"
echo "$image_names" | while IFS= read -r image; do
    echo "$image"


echo "$image_names" > "$OUTPUT_FILE"


done
rm findings.txt 2>/dev/null
rm trufflehog_*.json 2>/dev/null
rm gitleaks_*.json 2>/dev/null
rm filtered_data.json 2>/dev/null
rm trufflehog.json 2>/dev/null
rm -rf $CURRENTDIR/archives-imag* 2>/dev/null
./search_scan.sh
