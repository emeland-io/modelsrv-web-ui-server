GOLANGCI_LINT_VERSION ?= v2.11.4
TOOL_DIR := $(abspath bin)
GOLANGCI_LINT := $(TOOL_DIR)/golangci-lint

.PHONY: help ci mod-download mod-verify tools tool-golangci-lint lint vet build test tidy clean clean-tools run

help:
	@echo "Targets:"
	@echo "  make ci                 - mod download, verify, lint, build, test"
	@echo "  make lint               - run golangci-lint"
	@echo "  make build              - go build -v ./..."
	@echo "  make test               - go test -v -count=1 ./..."
	@echo "  make run                - run server locally"

.DEFAULT_GOAL := ci

ci: mod-download mod-verify lint build test

mod-download:
	go mod download

mod-verify:
	go mod verify

tools: tool-golangci-lint

tool-golangci-lint: $(GOLANGCI_LINT)

$(GOLANGCI_LINT):
	mkdir -p $(TOOL_DIR)
	GOBIN=$(TOOL_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run --timeout=5m ./...

vet:
	go vet ./...

build:
	go build -v ./...

test:
	go test -v -count=1 ./...

tidy:
	go mod tidy

clean:
	rm -f coverage.out coverage.html

clean-tools:
	rm -f $(GOLANGCI_LINT)

run:
	go run ./cmd/modelsrv-web-ui-server
