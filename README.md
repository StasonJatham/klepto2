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

```bash

sudo apt install git curl docker-compose

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

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing

Feel free to drop issues or propose commits.

## Authors and acknowledgment

Thanks goes to Maximilian Gutowski, Jakub Sucharkiewicz

## License

Project is licensed under GPL 3.0.
