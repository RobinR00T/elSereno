.PHONY: all build build-offensive build-sqlite install install-man \
        test test-race test-cover test-fuzz test-integration test-e2e test-all \
        bench sec lint fmt tidy clean run docker docker-sqlite \
        db-up db-down db-migrate db-reset \
        gen-manpages context-check ci

PREFIX ?= /usr/local
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

all: build

build:
	CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false \
	  -ldflags="$(LDFLAGS)" -o bin/elsereno ./cmd/elsereno

build-offensive:
	CGO_ENABLED=0 GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false \
	  -tags offensive -ldflags="$(LDFLAGS)" -o bin/elsereno-offensive ./cmd/elsereno

build-sqlite:
	CGO_ENABLED=1 go build -trimpath -buildvcs=false \
	  -tags sqlite -ldflags="$(LDFLAGS)" -o bin/elsereno-sqlite ./cmd/elsereno

install:
	go install ./cmd/elsereno

install-man: gen-manpages
	install -d $(DESTDIR)$(PREFIX)/share/man/man1 \
	            $(DESTDIR)$(PREFIX)/share/man/man5 \
	            $(DESTDIR)$(PREFIX)/share/man/man7
	install -m 644 man/man1/*.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 man/man5/*.5 $(DESTDIR)$(PREFIX)/share/man/man5/
	install -m 644 man/man7/*.7 $(DESTDIR)$(PREFIX)/share/man/man7/

test:
	go test -short ./...

test-race:
	go test -race -short -count=1 ./...

test-cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-fuzz:
	./scripts/run-fuzz.sh 30s

test-integration:
	go test -tags integration -count=1 ./test/integration/...

test-e2e:
	go test -tags e2e -count=1 ./test/e2e/...

test-all: test-race test-cover test-integration test-e2e

bench:
	go test -bench=. -benchmem -run=^$$ -benchtime=1s ./...

# bench-baseline runs the benchmarks three times and writes the
# result to benchmarks/baseline.txt. Regression detection on PRs
# compares the new run against this file via benchstat.
bench-baseline:
	@mkdir -p benchmarks
	go test -bench=. -benchmem -run=^$$ -count=3 -benchtime=500ms ./... \
		| tee benchmarks/baseline.txt

# bench-regression runs the current benchmarks and diffs against
# the checked-in baseline. Requires benchstat
# (go install golang.org/x/perf/cmd/benchstat@latest).
bench-regression:
	@mkdir -p benchmarks
	@[ -f benchmarks/baseline.txt ] || (echo "missing benchmarks/baseline.txt — run 'make bench-baseline'"; exit 1)
	go test -bench=. -benchmem -run=^$$ -count=3 -benchtime=500ms ./... \
		| tee benchmarks/current.txt
	benchstat benchmarks/baseline.txt benchmarks/current.txt

sec:
	gosec ./...
	govulncheck ./...
	trivy fs --exit-code 1 --severity HIGH,CRITICAL .
	go-licenses check ./... --disallowed_types=forbidden,restricted
	gitleaks detect --no-git --redact

lint:
	golangci-lint run

fmt:
	gofmt -w .
	goimports -w .

tidy:
	go mod tidy

clean:
	rm -rf bin/ dist/ coverage.*

run: build
	./bin/elsereno serve

docker:
	docker build -t elsereno:dev .

docker-sqlite:
	docker build -f Dockerfile.sqlite -t elsereno:sqlite-dev .

db-up:
	docker compose -f docker-compose.dev.yml up -d db

db-down:
	docker compose -f docker-compose.dev.yml down

db-migrate:
	./bin/elsereno db migrate up

db-reset:
	docker compose -f docker-compose.dev.yml down -v
	$(MAKE) db-up
	sleep 2
	$(MAKE) db-migrate

gen-manpages:
	./scripts/gen-manpages.sh

context-check:
	./scripts/context-check.sh

# `ci` replicates the remote CI locally as a superset so bitrot is caught
# before push (PITF-031). Includes all three build variants, test-race,
# test-cover, test-fuzz smoke, sec (including go-licenses), and context.
ci: lint build build-offensive build-sqlite test-race test-cover test-fuzz sec context-check
