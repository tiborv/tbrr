publish:
	KO_DOCKER_REPO=ghcr.io/tiborv/tbrr \
	ko build cmd/tbrr.go \
		--platform=all \
		--bare \
		--tags=$$(git describe --abbrev=0 --tags),latest