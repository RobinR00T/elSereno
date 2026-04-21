# syntax=docker/dockerfile:1.7
# Stay in sync with go.mod's `go` directive. When bumping, also
# update `internal/doctor` and the CI matrix. 1.25.4 on Alpine 3.22
# is the newest tag the library/golang image publishes that carries
# both the required Go version AND a patched Alpine userland.
ARG GO_VERSION=1.25.4
ARG ALPINE_VERSION=3.22
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
