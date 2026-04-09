# EDR Agent Makefile
# Build, test, package, and deploy the EDR agent across all platforms.
#
# Usage:
#   make build-linux       Build Linux amd64 binaries
#   make build-darwin      Build macOS amd64+arm64 binaries
#   make build-windows     Build Windows amd64 binaries
#   make build-all         Build for all platforms
#   make test              Run all Go tests
#   make package           Create release tarballs
#   make clean             Remove build artifacts

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOFLAGS := -trimpath
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE)

BIN_DIR     := bin
PROTO_DIR   := proto
PROTO_OUT   := pkg/protocol
GOPATH_BIN  := $(shell go env GOPATH 2>/dev/null)/bin
RULES_DIR   := rules
MODELS_DIR  := models
PACKAGE_DIR := dist

CLANG      ?= clang
BPF_ARCH   := $(shell uname -m 2>/dev/null | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' || echo "x86")
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Wall -Werror

.PHONY: build-linux build-darwin build-windows build-all
.PHONY: ebpf proto
.PHONY: test test-detection test-response test-race test-coverage
.PHONY: test-bench
.PHONY: vulncheck
.PHONY: rules-update intel-update models-update
.PHONY: models-bootstrap models-validate models-sign
.PHONY: train-all train-pe train-behavior train-network train-ransomware
.PHONY: install-linux install-darwin
.PHONY: package package-deb package-rpm package-pkg package-msi clean fmt lint vet

# ============================================================================
# Build targets
# ============================================================================

build-linux:
	@echo "==> Building Linux amd64 binaries"
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent-linux-amd64 ./cmd/agent
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-installer-linux-amd64 ./cmd/installer
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl-linux-amd64 ./cmd/cli

build-darwin:
	@echo "==> Building macOS binaries"
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent-darwin-amd64 ./cmd/agent
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent-darwin-arm64 ./cmd/agent
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl-darwin-amd64 ./cmd/cli
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl-darwin-arm64 ./cmd/cli

build-windows:
	@echo "==> Building Windows amd64 binaries"
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent-windows-amd64.exe ./cmd/agent
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl-windows-amd64.exe ./cmd/cli

build-all: build-linux build-darwin build-windows

# Build for the current platform only (development convenience).
build:
	@echo "==> Building for current platform"
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent ./cmd/agent
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-installer ./cmd/installer
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl ./cmd/cli
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-controlplane ./cmd/controlplane

# ============================================================================
# eBPF targets (Linux only)
# ============================================================================

EBPF_SRC := $(wildcard platform/linux/ebpf/*.c)
EBPF_OBJ := $(EBPF_SRC:.c=.o)

ebpf: $(EBPF_OBJ)
	@echo "==> eBPF programs compiled"

platform/linux/ebpf/%.o: platform/linux/ebpf/%.c platform/linux/ebpf/common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ============================================================================
# Protobuf generation
# ============================================================================

proto:
	@echo "==> Generating protobuf code"
	@mkdir -p $(PROTO_OUT)
	PATH="$(GOPATH_BIN):$$PATH" protoc --go_out=$(PROTO_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT) --go-grpc_opt=paths=source_relative \
		-I $(PROTO_DIR) \
		$(PROTO_DIR)/events.proto \
		$(PROTO_DIR)/alerts.proto \
		$(PROTO_DIR)/commands.proto \
		$(PROTO_DIR)/agent.proto

# ============================================================================
# Test targets
# ============================================================================

test:
	@echo "==> Running all tests"
	go test ./... -count=1 -timeout 120s

test-detection:
	@echo "==> Running detection engine tests"
	go test ./internal/detect/... -v -count=1 -timeout 60s
	go test ./internal/rules/... -v -count=1 -timeout 60s

test-response:
	@echo "==> Running response engine tests"
	go test ./internal/response/... -v -count=1 -timeout 60s

test-race:
	@echo "==> Running tests with race detector"
	go test ./... -race -count=1 -timeout 300s

test-coverage:
	@echo "==> Running tests with coverage"
	go test ./... -coverprofile=coverage.out -covermode=atomic -timeout 120s
	go tool cover -func=coverage.out
	@echo "==> HTML coverage report: coverage.html"
	go tool cover -html=coverage.out -o coverage.html

test-bench:
	@echo "==> Running benchmark suite"
	go test ./tests/benchmark/... -bench=. -benchmem -run=^$

# ============================================================================
# Rule, intel, and model updates
# ============================================================================

rules-update:
	@echo "==> Updating detection rules"
	@./scripts/update-rules.sh
	@echo "Rules update complete"

intel-update:
	@echo "==> Updating threat intelligence feeds"
	@./scripts/update-intel.sh
	@echo "IOC update complete"

models-update:
	@echo "==> Updating ML models"
	@mkdir -p $(MODELS_DIR)
	@if [ -x ./scripts/download-models.sh ]; then \
		./scripts/download-models.sh; \
	else \
		echo "download script missing or not executable"; \
		exit 1; \
	fi
	@echo "Model update complete"

models-bootstrap:
	@echo "==> Generating baseline ONNX models"
	python3 scripts/convert_pretrained.py baseline --output $(MODELS_DIR)
	@echo "Baseline models ready in $(MODELS_DIR)/"

models-validate:
	@echo "==> Validating ONNX models"
	python3 ml/training/export_onnx.py validate --model-dir $(MODELS_DIR)

models-sign:
	@echo "==> Signing ONNX models"
	@if [ -z "$(KEY)" ]; then echo "Usage: make models-sign KEY=path/to/key.pem"; exit 1; fi
	python3 scripts/convert_pretrained.py sign --models-dir $(MODELS_DIR) --key $(KEY)

# ============================================================================
# ML training targets
# ============================================================================

TRAIN_DATA   ?= ./data
TRAIN_OUTPUT ?= $(MODELS_DIR)
TRAIN_EPOCHS ?= 50

train-all: train-pe train-behavior train-network train-ransomware
	@echo "==> All models trained"

train-pe:
	@echo "==> Training PE classifier"
	cd ml && python3 -m training train --model pe --data $(TRAIN_DATA) --output $(TRAIN_OUTPUT)

train-behavior:
	@echo "==> Training behavior LSTM"
	cd ml && python3 -m training train --model behavior --data $(TRAIN_DATA) --output $(TRAIN_OUTPUT) --epochs $(TRAIN_EPOCHS)

train-network:
	@echo "==> Training network anomaly detector"
	cd ml && python3 -m training train --model network --data $(TRAIN_DATA) --output $(TRAIN_OUTPUT) --epochs $(TRAIN_EPOCHS)

train-ransomware:
	@echo "==> Training ransomware detector"
	cd ml && python3 -m training train --model ransomware --data $(TRAIN_DATA) --output $(TRAIN_OUTPUT)

# ============================================================================
# Install targets
# ============================================================================

install-linux: build-linux
	@echo "==> Installing on Linux"
	sudo $(BIN_DIR)/edr-installer-linux-amd64 install

install-darwin: build-darwin
	@echo "==> Installing on macOS"
	@ARCH=$$(uname -m); \
	if [ "$$ARCH" = "arm64" ]; then \
		sudo $(BIN_DIR)/edr-installer-darwin-arm64 install 2>/dev/null || \
		echo "Note: installer not built for darwin/arm64, use scripts/install.sh"; \
	else \
		sudo $(BIN_DIR)/edr-installer-darwin-amd64 install 2>/dev/null || \
		echo "Note: installer not built for darwin/amd64, use scripts/install.sh"; \
	fi

# ============================================================================
# Package targets
# ============================================================================

package: build-all
	@echo "==> Creating release packages"
	@mkdir -p $(PACKAGE_DIR)
	tar czf $(PACKAGE_DIR)/edr-$(VERSION)-linux-amd64.tar.gz \
		-C $(BIN_DIR) edr-agent-linux-amd64 edr-installer-linux-amd64 edrctl-linux-amd64 \
		-C .. configs/agent.yaml configs/agent.gov.yaml configs/agent.airgap.yaml \
		scripts/install.sh
	tar czf $(PACKAGE_DIR)/edr-$(VERSION)-darwin-amd64.tar.gz \
		-C $(BIN_DIR) edr-agent-darwin-amd64 edrctl-darwin-amd64 \
		-C .. configs/agent.yaml scripts/install.sh
	tar czf $(PACKAGE_DIR)/edr-$(VERSION)-darwin-arm64.tar.gz \
		-C $(BIN_DIR) edr-agent-darwin-arm64 edrctl-darwin-arm64 \
		-C .. configs/agent.yaml scripts/install.sh
	cd $(BIN_DIR) && zip ../$(PACKAGE_DIR)/edr-$(VERSION)-windows-amd64.zip \
		edr-agent-windows-amd64.exe edrctl-windows-amd64.exe
	@echo "==> Packages created in $(PACKAGE_DIR)/"
	@ls -lh $(PACKAGE_DIR)/

package-deb: build-linux
	@echo "==> Creating .deb package"
	./scripts/package_linux.sh

package-rpm: build-linux
	@echo "==> Creating .rpm package"
	EDR_SKIP_DEB=1 ./scripts/package_linux.sh

package-pkg: build-darwin
	@echo "==> Creating macOS .pkg installer"
	./scripts/package_macos.sh

package-msi: build-windows
	@echo "==> Creating Windows installer zip"
	./scripts/package_windows.sh

# ============================================================================
# Code quality
# ============================================================================

fmt:
	@echo "==> Formatting code"
	gofmt -s -w .

lint:
	@echo "==> Running linters"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; running go vet only"; \
		go vet ./...; \
	fi

vet:
	@echo "==> Running go vet"
	go vet ./...

vulncheck:
	@echo "==> Running govulncheck"
	@if command -v govulncheck >/dev/null 2>&1; then \
		GOTOOLCHAIN=auto govulncheck ./...; \
	else \
		echo "govulncheck not installed"; \
		exit 1; \
	fi

# ============================================================================
# Clean
# ============================================================================

clean:
	@echo "==> Cleaning build artifacts"
	rm -rf $(BIN_DIR)/ $(PACKAGE_DIR)/ coverage.out coverage.html
	rm -f platform/linux/ebpf/*.o
	rm -f $(PROTO_OUT)/*.pb.go
	@echo "==> Clean complete"
