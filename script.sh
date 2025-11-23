#!/bin/sh

# Init
# Change APIKEY to your Dockerhub personal Token
APIKEY="dckr_pat_aSYdYzdJrezHx9-5UhKvd7yXqw8"
CURRENTDATE=$(date '+%Y%m%d')
CURRENTDIR=$(pwd)
IMAGETAR=image.tar
ARCHIVEDIR=$(pwd)"/archives-image/"
ARCHIVETARDIR=$(pwd)"/archives-image-tar/"
# Check result directories exist
[ ! -d "$ARCHIVEDIR" ] && mkdir -p "$ARCHIVEDIR"
[ ! -d "$ARCHIVETARDIR" ] && mkdir -p "$ARCHIVETARDIR"
URL=""
LIMIT=""
NAMESPACE=""
SPECIFICREPO=""
COUNTER=1
SKIP=0

# Functions
download() {
	echo "----"
	echo "- Downloading $DOCKERURL/$1"
	echo "----"
	docker pull $1
       	#docker save $DOCKERURL/$1 -o $ARCHIVEDIR/$(echo "$1" | sed 's/\//--/g' | sed 's/:/--/g').tar
	docker save $1 -o $ARCHIVEDIR$IMAGETAR
	docker rmi $1
#	unpack
#	rm $ARCHIVEDIR/*.tar
}

unpack() {
    # Loop through all .tar files in the specified directory
    for tarfile in "$ARCHIVEDIR"/*.tar; do
        # Check if the file exists
        [ -e "$tarfile" ] || continue  # Skip if no tar files are found

        # Strip the .tar extension for the directory name
        dir="${tarfile%.tar}"

        echo "Unpacking $tarfile into $dir..."

        # Create a directory with the same name as the tar file (without extension)
        mkdir -p "$dir"

        # Unpack the tar file into the directory
        tar -xf "$tarfile" -C "$dir"

        # Change to the directory
        cd "$dir" || exit

        # Loop through all 'layer.tar' files within the unpacked contents
        for layertar in $(find . -type f -name layer.tar); do
            echo "$dir: Extracting layer.tar for layer $(dirname "$layertar")"

            # Change to the directory containing 'layer.tar'
            cd "$(dirname "$layertar")" || exit

            # Unpack 'layer.tar'
            tar -xf layer.tar
			rm -rf layer.tar
            # Return to the previous directory
            cd - || exit
        done

        # Return to the original directory
        cd - || exit

        # Move the original tar file to the ARCHIVETARDIR
        mv "$tarfile" "$ARCHIVETARDIR/$(basename "$tarfile")"
    done
}

# Usage

while getopts u:l:s:n:r:t:o opt 
do
	case $opt in
		u) URL=$OPTARG;;
		l) LIMIT=$OPTARG;;
		s) SKIP=$OPTARG;;
		n) NAMESPACE=$OPTARG;;
		r) SPECIFICREPO=$OPTARG;;
		t) TIME=$OPTARG;;
		o) unpack; exit 0;;
		?) echo "$USAGE"; exit 0;;
	esac
done

if [ -z $URL ]
then
	echo "$USAGE"
	echo "----"
	echo "- Url parameter is mandatory"
	echo "----"
	exit 0
fi

if [ -z $TIME ]
then
	# Beginning of Unix time stamp (date -d 1970-01-01 +%s => 0)
	timestamp=0
else
	timestamp=$(date -d $TIME +%s)
fi

if [ -z $APIKEY ]
then
	echo "EXITTING: You have to provide an API key!"
	exit
fi

API_KEY_SUCCESSFUL=$(curl "$URL/api/v1/repository?public=true&last_modified=true" -H "Authorization: Bearer $APIKEY"|grep  -oc "invalid_token")
API_KEY_FAILED=$(curl "$URL/api/v1/user/" -H "Authorization: Bearer $APIKEY"|grep  -oc "invalid_token")
if [ -z $API_KEY_FAILED ]
then
	echo "EXITTING: The provided API key is invalid!"
	exit
fi


# Post Init
#DOCKERURL=$(echo "$URL" | sed 's/http\(s\):\/\///g' | sed 's/\///g')
#DOCKERURL=$SPECIFICREPO

mkdir -p $ARCHIVEDIR

# Start

# Fetch only specific repo
if [ ! -z "$SPECIFICREPO" ]
then

	download "$SPECIFICREPO:latest"
#	done
	unpack
	exit 0
fi

# Case 1) No restriction on Namespace 
if [ -z "$NAMESPACE" ]
then
	next_page=""
	is_next=1
	while [ $is_next -eq 1 ]
	do
		reposjson=$(curl "$URL/api/v1/repository?public=true&last_modified=true&next_page=$next_page" -H "Authorization: Bearer $APIKEY")
		next_page=$(echo $reposjson | jq -r '.next_page')
		# Debugging: echo "NEXT PAGE - $next_page"
		if [ ! -z $next_page ] && [ $next_page != "null" ]
		then
			for repo in $(echo $reposjson |jq -r '.repositories[] | .namespace + "/" + .name'); do
				# Skip iteration
				if [ $SKIP -gt 0 ]
				then
					echo "Skip $SKIP: $repo"
					let "SKIP--"
					continue
				fi
				# iteration includes check for timestamp of tag
				for tag in $(curl "$URL/api/v1/repository/$repo/tag/?limit=1&page=1&onlyActiveTags=true" -H "Authorization: Bearer $APIKEY" | jq -r ".tags[] | select(.start_ts >= $timestamp) | .name"); do
					download "$repo:$tag"
					if [ ! -z "$LIMIT" ] && [ "$LIMIT" == "$COUNTER" ]
					then
						echo "Reached limit"
						unpack
						exit 0
					elif [ ! -z "$LIMIT" ]
					then
						let "COUNTER++"
					fi
				done
			done
		else
			is_next=0
		fi
	done
# Case 2) Restriction on Namespace (TODO: paging not supported. Is it needed?)
else
	for repo in $(curl "$URL/api/v1/repository?namespace=$NAMESPACE&public=true&last_modified=true" -H "Authorization: Bearer $APIKEY" |jq -r '.repositories[] | .namespace + "/" + .name'); do
		# Skip iteration
		if [ $SKIP -gt 0 ]
		then
			echo "Skip $SKIP: $repo"
			let "SKIP--"
			continue
		fi

		for tag in $(curl "$URL/api/v1/repository/$repo/tag/?limit=99&page=1&onlyActiveTags=true" -H "Authorization: Bearer $APIKEY"| jq -r "[.tags[]|select (.size > 500)][0].name"); do
			download "$repo:$tag"
			if [ ! -z "$LIMIT" ] && [ "$LIMIT" == "$COUNTER" ]
			then
				echo "Reached limit"
				unpack
				exit 0
			elif [ ! -z "$LIMIT" ]
			then
				let "COUNTER++"
			fi
		done
	done
fi


echo "Finished!"
