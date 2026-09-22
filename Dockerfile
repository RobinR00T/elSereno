# syntax=docker/dockerfile:1.7
# Stay in sync with go.mod (bumped to go 1.26.0 / toolchain go1.26.6
# with the pgx 5.11 update) and the CI matrix. 1.26.6 on Alpine 3.24
# is the library/golang tag that carries both the toolchain Go version
# AND a patched Alpine userland (the 1.26 patches moved off Alpine
# 3.22, whose newest 1.26 tag is only 1.26.0).
ARG GO_VERSION=1.26.6
ARG ALPINE_VERSION=3.24
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

WORKDIR /src

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /out/elsereno ./cmd/elsereno

# Runtime — distroless nonroot.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/elsereno /usr/local/bin/elsereno
USER nonroot:nonroot
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/elsereno"]
CMD ["serve"]
