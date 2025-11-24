# Klepto - A Docker Image Scanner

Klepto is a docker-image search tool, extraction and secrets searcher within found docker images. 
Use SEARCH_VALUE as Variable Name and the content as the Search Term (e.g. "telekom") to find docker images containing 
the Search Term in the Name or description on the public dockerhub.

#dockerimage
#secrets
#truffle_hog
#gitleaks



## Installation

Tested on debian bookworm
Tested on WSL ubuntu:
Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 4.4.0-19041-Microsoft x86_64)

```bash

sudo apt install git curl jq docker.io python3 docker-registry docker-compose

git clone https://github.com/telekom-security/klepto.git 
```

## Usage

```bash
sudo ./search.sh SEARCHTERM


EDIT /script.sh
Change APIKEY


EDIT /parser.py
Change desired_detector_type = [2, 3, 7, 9, 15, 17, 18, 31, 39, 40, 48, 69, 71, 120, 177, 350, 353, 582, 584, 599, 737, 924]
undesired_terms = ["example", "test", "dummy", "sample"]
```

## Run with Docker

```bash
# Build the image
docker build -t klepto .

# Run the search workflow (mount the Docker socket so the scripts can pull/save images)
docker run --rm -it \
  -e APIKEY=<your_dockerhub_pat> \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/app \
  klepto <search-term>

# Run a different script (example: pull a specific repository)
docker run --rm -it \
  -e APIKEY=<your_dockerhub_pat> \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/app \
  --entrypoint ./script.sh \
  klepto -r namespace/name -u https://hub.docker.com/
```

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing

Feel free to drop issues or propose commits.

## Authors and acknowledgment

Thanks goes to Maximilian Gutowski, Jakub Sucharkiewicz

## License

Project is licensed under GPL 3.0.
