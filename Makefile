BINARY      := sysaudit
PKG         := github.com/njhoffman/sysaudit
BIN_DIR     := bin
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
               -X $(PKG)/internal/version.Version=$(VERSION) \
               -X $(PKG)/internal/version.Commit=$(COMMIT) \
               -X $(PKG)/internal/version.Date=$(DATE)

# TEST_RUNNER selects how go test output is rendered.
# Valid values: go (default), gotestsum, gotestfmt, tparse
TEST_RUNNER ?= go
TEST_PKGS   ?= ./...
TEST_FLAGS  ?= -race -count=1

.PHONY: all build install clean lint vet fmt test test-one cover manpage tools help

all: lint test build

build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) ./cmd/$(BINARY)

install:
	go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/$(BINARY)

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

fmt:
	gofmt -s -w .

vet:
	go vet ./...

lint:
	golangci-lint run

test:
ifeq ($(TEST_RUNNER),gotestsum)
	gotestsum --format pkgname -- $(TEST_FLAGS) $(TEST_PKGS)
else ifeq ($(TEST_RUNNER),gotestfmt)
	go test -json $(TEST_FLAGS) $(TEST_PKGS) | gotestfmt
else ifeq ($(TEST_RUNNER),tparse)
	go test -json $(TEST_FLAGS) $(TEST_PKGS) | tparse -all
else
	go test $(TEST_FLAGS) $(TEST_PKGS)
endif

# Run a single test: make test-one PKG=./internal/config NAME=TestLoad
test-one:
	@test -n "$(PKG_)" || (echo "usage: make test-one PKG=./path NAME=TestX" >&2; exit 2)
	go test $(TEST_FLAGS) -run '^$(NAME)$$' -v $(PKG_)

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "coverage report: coverage.html"

# Pinned go-md2man version. Bump deliberately; reproducible builds matter
# more here than chasing latest.
MD2MAN_VERSION ?= v2.0.4

manpage: man/sysaudit.1

man/sysaudit.1: man/sysaudit.1.md
	go run github.com/cpuguy83/go-md2man/v2@$(MD2MAN_VERSION) \
		-in man/sysaudit.1.md -out man/sysaudit.1
	@echo "wrote man/sysaudit.1 (preview: man -l man/sysaudit.1)"

tools:
	@echo "Required tools (install with: go install ...):"
	@echo "  github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
	@echo "  gotest.tools/gotestsum@latest"
	@echo "  github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@latest"
	@echo "  github.com/mfridman/tparse@latest"

help:
	@echo "Targets:"
	@echo "  build         Build $(BINARY) into $(BIN_DIR)/"
	@echo "  install       go install the binary"
	@echo "  test          Run tests (TEST_RUNNER=go|gotestsum|gotestfmt|tparse)"
	@echo "  test-one      Run a single test (PKG_=./path NAME=TestX)"
	@echo "  lint          Run golangci-lint"
	@echo "  vet           Run go vet"
	@echo "  fmt           Run gofmt -s -w"
	@echo "  cover         Generate coverage.html"
	@echo "  manpage       Generate the manpage"
	@echo "  clean         Remove build artifacts"
	@echo "  tools         List required dev tools"
