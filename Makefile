# go-cotp — X.224 / COTP TPDU library (package at repo root)

SHELL := /bin/bash
GO   ?= go
PKGS := .

COVERAGE_MIN := 75

.PHONY: help test test-race test-short vet lint lint-ci fmt vuln fuzz fuzz-decode fuzz-parse bench tidy check check-full clean coverage coverage-html coverage-clean coverage-check

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z0-9_.-]+:.*## / {printf "%-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run tests
	@echo "Running tests..."
	$(GO) test $(PKGS)

test-short: ## Run tests (short mode)
	@echo "Running tests (short)..."
	$(GO) test -short $(PKGS)

test-race: ## Run tests with race detector
	@echo "Running tests with race detector..."
	$(GO) test -race $(PKGS)

vet: ## Run go vet
	@echo "Running go vet..."
	$(GO) vet $(PKGS)

lint: ## Run staticcheck
	@echo "Running staticcheck"
	@staticcheck $(PKGS)

lint-ci: ## Run golangci-lint
	@echo "Running golangci-lint"
	@golangci-lint run $(PKGS)

vuln: ## Run govulncheck
	@echo "Running govulncheck"
	@govulncheck $(PKGS)

fmt: ## Run go fmt
	@echo "Running go fmt..."
	@gofmt -w .

coverage: ## Run tests with coverage profile and text summary
	@echo "Running coverage..."
	$(GO) test -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out | tee coverage.txt

coverage-html: coverage ## Generate HTML coverage report
	@echo "Generating HTML coverage report..."
	$(GO) tool cover -html=coverage.out -o coverage.html

coverage-clean: ## Remove coverage artifacts
	@echo "Removing coverage artifacts..."
	rm -f coverage.out coverage.txt coverage.html

coverage-check: ## Run tests and fail if coverage is below $(COVERAGE_MIN)%%
	@echo "Running coverage (minimum $(COVERAGE_MIN)%%)..."
	$(GO) test -coverprofile=coverage.out $(PKGS)
	@go tool cover -func=coverage.out | grep 'total:' | awk -v min=$(COVERAGE_MIN) '{gsub(/%/,""); p=$$NF+0; if (p < min) { printf "Coverage %.1f%% is below %d%%\n", p, min; exit 1 } else { printf "Coverage %.1f%% (>= %d%%)\n", p, min } }'

fuzz: ## Run short fuzz tests (Decode + parse)
	@echo "Running fuzz tests..."
	$(GO) test -fuzz=FuzzDecode -fuzztime=5s $(PKGS)
	$(GO) test -fuzz=FuzzParseVariablePart -fuzztime=5s $(PKGS)

fuzz-decode: ## Run Decode fuzz target
	@echo "Running Decode fuzz target..."
	$(GO) test -fuzz=FuzzDecode -fuzztime=10s $(PKGS)

fuzz-parse: ## Run parse fuzz targets
	@echo "Running parse fuzz targets..."
	$(GO) test -fuzz=FuzzParseVariablePart -fuzztime=10s $(PKGS)
	$(GO) test -fuzz=FuzzParseCRCCVariablePart -fuzztime=10s $(PKGS)

bench: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GO) test -run=^$$ -bench=. -benchmem $(PKGS)

tidy: ## Tidy module files
	@echo "Tidying module files..."
	$(GO) mod tidy

check: fmt tidy vet lint lint-ci vuln test test-race coverage ## Run core release checks
	@echo "Check done."

check-full: check ## Alias for check
	@echo "Check-full done."

clean: ## Clean test cache and coverage artifacts
	@echo "Cleaning test cache..."
	$(GO) clean -testcache
	$(MAKE) coverage-clean
