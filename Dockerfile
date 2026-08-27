FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.26 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

ARG GIT_COMMIT
ARG VERSION
ARG PUBLIC_KEY

ENV GO111MODULE=on
ENV GOFLAGS=-mod=vendor
ENV CGO_ENABLED=0

RUN echo "Checking public key" && test -n "$PUBLIC_KEY"

WORKDIR /go/src/github.com/openfaasltd/signet
COPY . .

# Run a gofmt and exclude all vendored code.
RUN test -z "$(gofmt -l $(find . -type f -name '*.go' -not -path "./vendor/*"))" || { echo "Run \"gofmt -s -w\" on your Golang code"; exit 1; }

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 \
    go build --ldflags "-s -w \
    -X main.PublicKey=${PUBLIC_KEY} \
    -X main.Version=${VERSION} \
    -X main.GitCommit=${GIT_COMMIT}" \
    -o /usr/bin/signet .

# scratch is the only house base image that exists for every target
# platform (distroless and alpine are linux-only). The static binary runs
# as the numeric nonroot uid 65532, matching the k8s init container.
FROM --platform=${TARGETPLATFORM:-linux/amd64} scratch
COPY --from=builder /usr/bin/signet /signet
# Needed for federated login (and any other outbound TLS): the daemon talks
# to GitHub's device/token/API endpoints.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/signet"]
