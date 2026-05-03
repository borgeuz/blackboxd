# blackboxd — build, test, ship.
#
# All `build*` targets produce statically-linked, stripped, reproducible
# binaries (CGO_ENABLED=0, -trimpath, -buildid="", -s -w). Reproducibility
# is verified by `make reproducible-check`.
#
# Cross-compilation targets cover linux/amd64, linux/arm64, linux/arm/7,
# linux/arm/6 — the supported customer-device set.

BIN          := blackboxd
PKG          := github.com/borgeuz/blackboxd
CMD          := ./cmd/blackboxd
DIST         := dist

VERSION      ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo "dev")
COMMIT       ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

VERSION_PKG  := $(PKG)/internal/version
LDFLAGS      := -s -w -buildid= \
                -X $(VERSION_PKG).Version=$(VERSION) \
                -X $(VERSION_PKG).Commit=$(COMMIT) \
                -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)
GO_BUILD_FLAGS := -trimpath -buildvcs=true -ldflags='$(LDFLAGS)'

# CGO is disabled globally — pure Go is non-negotiable per spec.
export CGO_ENABLED := 0

# Host OS/arch, queried independently of any GOOS/GOARCH the user (or
# `go env -w`) may have configured. Used by `make test` to ensure tests
# run as a native binary rather than a cross-compiled one we cannot
# execute.
HOST_GOOS    := $(shell go env GOHOSTOS)
HOST_GOARCH  := $(shell go env GOHOSTARCH)

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build for host arch (stripped, static, reproducible).
	go build $(GO_BUILD_FLAGS) -o $(BIN) $(CMD)

.PHONY: build-all
build-all: $(DIST)/$(BIN)-linux-amd64 $(DIST)/$(BIN)-linux-arm64 $(DIST)/$(BIN)-linux-armv7 $(DIST)/$(BIN)-linux-armv6 ## Build all four target architectures.

$(DIST)/$(BIN)-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $@ $(CMD)

$(DIST)/$(BIN)-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $@ $(CMD)

$(DIST)/$(BIN)-linux-armv7:
	GOOS=linux GOARCH=arm GOARM=7 go build $(GO_BUILD_FLAGS) -o $@ $(CMD)

$(DIST)/$(BIN)-linux-armv6:
	GOOS=linux GOARCH=arm GOARM=6 go build $(GO_BUILD_FLAGS) -o $@ $(CMD)

.PHONY: test
test: ## Run unit tests with race detector + verify module hashes.
	@# Tests must run on the host architecture; cross-compiling to
	@# linux/arm64 from a darwin host can't execute the resulting
	@# binary. We pin GOOS/GOARCH to the host for this target so the
	@# global build defaults remain untouched.
	GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) GOARM= CGO_ENABLED=1 go test -race -count=1 ./...
	go mod verify

.PHONY: vet
vet: ## go vet.
	go vet ./...

.PHONY: fmt
fmt: ## gofmt -s -w.
	gofmt -s -w .

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt -s clean.
	@out=$$(gofmt -s -l .); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

.PHONY: bench
bench: ## Run all benchmarks.
	GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) GOARM= go test -bench=. -benchmem -run=^$$ ./...

.PHONY: fuzz
fuzz: ## Run fuzz targets for FUZZ_DURATION (default 30s) each.
	@duration=$${FUZZ_DURATION:-30s}; \
	for pkg in $$(go list ./... | xargs -n1 -I{} sh -c 'grep -l "^func Fuzz" $$(go list -f "{{.Dir}}" {})/*_test.go 2>/dev/null && echo {}' | awk '{print $$NF}' | sort -u); do \
	  for fn in $$(grep -h "^func Fuzz" $$(go list -f "{{.Dir}}" $$pkg)/*_test.go | sed -E 's/func (Fuzz[A-Za-z0-9_]+).*/\1/'); do \
	    echo "==> $$pkg $$fn for $$duration"; \
	    GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) GOARM= go test -run=^$$ -fuzz=^$$fn$$ -fuzztime=$$duration $$pkg || exit 1; \
	  done; \
	done

.PHONY: reproducible-check
reproducible-check: ## Build twice, assert byte-identical.
	@# Pin VERSION/COMMIT/BUILD_DATE explicitly so the two builds see
	@# the same -X ldflag values; otherwise the recursive $(shell ...)
	@# expansion can pick up a different second on the wall clock.
	@d=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	v="$(VERSION)"; c="$(COMMIT)"; \
	$(MAKE) --no-print-directory build BIN=$(BIN).repro1 VERSION=$$v COMMIT=$$c BUILD_DATE=$$d; \
	$(MAKE) --no-print-directory build BIN=$(BIN).repro2 VERSION=$$v COMMIT=$$c BUILD_DATE=$$d; \
	if cmp -s $(BIN).repro1 $(BIN).repro2; then \
	  echo "reproducible-check: OK"; rm -f $(BIN).repro1 $(BIN).repro2; \
	else \
	  echo "reproducible-check: FAIL — outputs differ"; \
	  ls -l $(BIN).repro1 $(BIN).repro2; exit 1; \
	fi

.PHONY: clean
clean: ## Remove build artifacts.
	rm -rf $(DIST) $(BIN) $(BIN).repro1 $(BIN).repro2
