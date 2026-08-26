FROM golang:1.25 AS build

ARG PUBLIC_KEY
ARG VERSION=dev
ARG GIT_COMMIT=none

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.PublicKey=${PUBLIC_KEY} -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT}" \
    -o /signet .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /signet /signet
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/signet"]
