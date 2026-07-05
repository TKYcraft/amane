ARG GO_VERSION=1.25.5

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    mkdir -p /out && \
    for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
        goos="${platform%/*}"; goarch="${platform#*/}"; \
        out="/out/amane-${goos}-${goarch}"; \
        echo "→ ${out}"; \
        CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -trimpath \
            -ldflags "-s -w -X main.version=${VERSION}" \
            -o "$out" ./cmd/amane; \
    done && \
    (cd /out && sha256sum amane-* > SHA256SUMS)

FROM scratch AS dist
COPY --from=builder /out/ /
