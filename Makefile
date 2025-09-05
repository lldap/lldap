build-dev-container:
	docker buildx build --tag lldap/rust-dev --file .github/workflows/Dockerfile.dev --push .github/workflows

prepare-release:
	./prepare-release.sh
