IMG ?= {CONTAINER_IMAGE}

test: fmt vet
	go test ./... -coverprofile cover.out

fmt:
	go fmt ./...

vet:
	go vet ./...

build: fmt vet test
	go build -a -o bin/egress-watcher *.go

# Build the docker image
docker-build: test
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}