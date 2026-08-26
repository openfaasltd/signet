IMG_NAME?=signet
PUBLIC_KEY := $(shell ./hack/get-public-key.sh)

GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo none)
VERSION := $(shell git describe --tags --dirty 2>/dev/null || echo dev)
GIT_UNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GIT_UNTRACKEDCHANGES),)
	GIT_COMMIT := $(GIT_COMMIT)-dirty
endif

TAG?=$(VERSION)
OWNER?=alexellis2
SERVER?=docker.io
PLATFORMS?=linux/amd64,linux/arm64,darwin/arm64

LDFLAGS := "-s -w -X main.PublicKey=$(PUBLIC_KEY) -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT)"
export GO111MODULE=on

.PHONY: all
all: gofmt test dist hash

.PHONY: gofmt
gofmt:
	@test -z "$$(gofmt -l -s $$(find . -type f -name '*.go' -not -path './vendor/*'))" || { echo "Run \"gofmt -s -w\" on your Golang code"; exit 1; }

.PHONY: test
test:
	CGO_ENABLED=0 go test $$(go list ./... | grep -v /vendor/) -cover

.PHONY: local
local:
	mkdir -p bin/
	CGO_ENABLED=0 go build -ldflags $(LDFLAGS) -o bin/signet

.PHONY: dist
dist:
	mkdir -p bin/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags $(LDFLAGS) -o bin/signet
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags $(LDFLAGS) -o bin/signet-arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags $(LDFLAGS) -o bin/signet-darwin-arm64

.PHONY: hash
hash:
	rm -f bin/checksums.sha256 && cd bin/ && shasum -a 256 signet* > checksums.sha256

.PHONY: build
build:
	@echo $(SERVER)/$(OWNER)/$(IMG_NAME):$(TAG) && \
	docker buildx create --use --name=multiarch --node=multiarch && \
	docker buildx build \
		--platform $(PLATFORMS) \
		--push=false \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg VERSION=$(VERSION) \
		--build-arg PUBLIC_KEY=$(PUBLIC_KEY) \
		--tag $(SERVER)/$(OWNER)/$(IMG_NAME):$(TAG) \
		.

.PHONY: publish
publish:
	@test "$(TAG)" != "dev" || (echo "TAG must be an explicit release version, e.g. v0.0.3" && exit 1)
	@echo $(SERVER)/$(OWNER)/$(IMG_NAME):$(TAG) && \
	docker buildx create --use --name=multiarch --node=multiarch && \
	docker buildx build \
		--platform $(PLATFORMS) \
		--push=true \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg VERSION=$(VERSION) \
		--build-arg PUBLIC_KEY=$(PUBLIC_KEY) \
		--tag $(SERVER)/$(OWNER)/$(IMG_NAME):$(TAG) \
		.
