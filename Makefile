Version := $(shell git describe --tags --dirty 2>/dev/null || echo dev)
GitCommit := $(shell git rev-parse HEAD 2>/dev/null || echo none)
# PublicKey is the base64-encoded ECDSA public key (key.pub) shared with
# faas-netes / inlets-pro. It is baked into the binary for license validation.
PUBLIC_KEY := $(shell base64 < key.pub | tr -d '\n')

LDFLAGS := "-s -w -X main.PublicKey=$(PUBLIC_KEY) -X main.Version=$(Version) -X main.GitCommit=$(GitCommit)"
export GO111MODULE=on
SOURCE_DIRS = main.go cmd pkg

IMG_NAME?=signet
TAG?=latest
OWNER?=openfaasltd
SERVER?=ghcr.io
PLATFORMS?=linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64

.PHONY: all
all: gofmt test dist hash

.PHONY: gofmt
gofmt:
	@test -z $(shell gofmt -l -s $(SOURCE_DIRS) ./ | grep -v vendor/ | tee /dev/stderr) || (echo "[WARN] Fix formatting issues with 'make gofmt'" && exit 1)

.PHONY: test
test:
	CGO_ENABLED=0 go test $(shell go list ./... | grep -v /vendor/ | xargs echo) -cover

.PHONY: local
local:
	mkdir -p bin/
	CGO_ENABLED=0 go build -ldflags $(LDFLAGS) -o bin/signet

.PHONY: dist
dist:
	mkdir -p bin/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags $(LDFLAGS) -o bin/signet
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags $(LDFLAGS) -o bin/signet-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags $(LDFLAGS) -o bin/signet-armhf
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags $(LDFLAGS) -o bin/signet-darwin
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags $(LDFLAGS) -o bin/signet-darwin-arm64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags $(LDFLAGS) -o bin/signet.exe

.PHONY: hash
hash:
	rm -rf bin/*.sha256 && cd bin/ && shasum -a 256 signet* > checksums.sha256

.PHONY: build
build:
	@echo $(SERVER)/$(OWNER)/$(IMG_NAME):$(TAG) && \
	docker buildx create --use --name=multiarch --node=multiarch && \
	docker buildx build \
		--platform $(PLATFORMS) \
		--push=false \
		--build-arg GIT_COMMIT=$(GitCommit) \
		--build-arg VERSION=$(Version) \
		--build-arg PUBLIC_KEY=$(PUBLIC_KEY) \
		--tag $(SERVER)/$(OWNER)/$(IMG_NAME):$(TAG) \
		.

.PHONY: publish
publish:
	@echo $(SERVER)/$(OWNER)/$(IMG_NAME):$(TAG) && \
	docker buildx create --use --name=multiarch --node=multiarch && \
	docker buildx build \
		--platform $(PLATFORMS) \
		--push=true \
		--build-arg GIT_COMMIT=$(GitCommit) \
		--build-arg VERSION=$(Version) \
		--build-arg PUBLIC_KEY=$(PUBLIC_KEY) \
		--tag $(SERVER)/$(OWNER)/$(IMG_NAME):$(TAG) \
		.
