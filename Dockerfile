# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.23.4
FROM golang:${GO_VERSION}-alpine3.20 AS builder

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
