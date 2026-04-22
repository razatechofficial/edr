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
.PHONY: bundle-enterprise build-installer-embedded
.PHONY: ebpf ebpf-link ebpf-install proto
.PHONY: test test-collector test-detection test-response test-race test-coverage
.PHONY: run-agent run-agent-ml test-edr-macos-lab
.PHONY: test-bench
.PHONY: vulncheck
.PHONY: rules-update intel-update models-update
.PHONY: models-bootstrap models-validate models-sign
.PHONY: train-all train-pe train-behavior train-network train-ransomware
.PHONY: install-linux install-darwin install-embedded edrctl
.PHONY: package package-deb package-rpm package-pkg package-pkg-consumer notarize-pkg-consumer package-msi clean fmt lint vet

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
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-installer-darwin-amd64 ./cmd/installer
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-installer-darwin-arm64 ./cmd/installer
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

# Rebuild only the CLI (handy after config-path changes). Do not pass “# …” on the same line:
# some environments treat it as extra make goals and you get: No rule to make target '#'.
edrctl:
	@echo "==> Building edrctl"
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl ./cmd/cli

# ============================================================================
# eBPF targets (Linux only)
# ============================================================================

EBPF_SRC     := $(wildcard platform/linux/ebpf/*.c)
EBPF_OBJ     := $(EBPF_SRC:.c=.o)
EBPF_MERGED  := platform/linux/ebpf/edr.bpf.o
EBPF_INSTALL := /var/lib/edr/bpf/edr.bpf.o
VMLINUX_H    := platform/linux/ebpf/vmlinux.h
VMLINUX_FALLBACK := platform/linux/ebpf/vmlinux_fallback.h
LLVM_LINK    ?= llvm-link
BPFTOOL      ?= bpftool

$(VMLINUX_H):
	@if command -v $(BPFTOOL) >/dev/null 2>&1 && [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "==> Generating vmlinux.h from kernel BTF"; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
	elif [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "bpftool not found; install bpftool to generate vmlinux.h" >&2; \
		exit 1; \
	else \
		echo "BTF not available on this kernel; using fallback vmlinux.h"; \
		cp $(VMLINUX_FALLBACK) $(VMLINUX_H); \
	fi

ebpf: $(VMLINUX_H) $(EBPF_OBJ)
	@echo "==> eBPF programs compiled"

platform/linux/ebpf/%.o: platform/linux/ebpf/%.c platform/linux/ebpf/common.h $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ebpf-link: $(EBPF_OBJ)
	@echo "==> Linking eBPF objects into single edr.bpf.o"
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		$(BPFTOOL) gen object $(EBPF_MERGED) $(EBPF_OBJ); \
	elif command -v $(LLVM_LINK) >/dev/null 2>&1; then \
		$(LLVM_LINK) -o $(EBPF_MERGED) $(EBPF_OBJ); \
	else \
		echo "ERROR: Neither bpftool nor llvm-link found. Install one of them."; \
		exit 1; \
	fi
	@echo "==> Linked: $(EBPF_MERGED)"

ebpf-install: ebpf-link
	@echo "==> Installing eBPF bytecode to $(EBPF_INSTALL)"
	@sudo mkdir -p $(dir $(EBPF_INSTALL))
	@sudo install -m 644 $(EBPF_MERGED) $(EBPF_INSTALL)
	@echo "==> Installed: $(EBPF_INSTALL)"

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

# Collector package without CGO (avoids macOS EndpointSecurity link in CI/dev).
test-collector:
	@echo "==> Collector unit tests (CGO_ENABLED=0)"
	CGO_ENABLED=0 go test ./internal/collector/... -count=1 -timeout 60s

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

# Run agent from repo root with configs/agent.yaml (cwd must be the repo root).
run-agent:
	go run ./cmd/agent run --config configs/agent.yaml --debug

# Same as run-agent but prepends common macOS Homebrew ONNX library paths so
# libonnxruntime.dylib resolves. Set ml.require_runtime: true (or ML_REQUIRE_RUNTIME=true)
# to fail fast if ONNX or the full advanced engine cannot start.
run-agent-ml:
	DYLD_LIBRARY_PATH=/opt/homebrew/lib:/usr/local/lib:$$DYLD_LIBRARY_PATH \
	go run ./cmd/agent run --config configs/agent.yaml --debug

# Benign macOS lab: Sigma parse smoke + Log4j YARA probe + manifest (see scripts/test_edr_macos_lab.sh).
test-edr-macos-lab:
	@./scripts/test_edr_macos_lab.sh

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
	@echo "==> Staging rules next to installer (edr-installer copies from its directory)"
	@if [ ! -d "$(RULES_DIR)" ]; then echo "error: $(RULES_DIR) not found — cannot bundle baseline/YARA/Sigma rules"; exit 1; fi
	@mkdir -p "$(BIN_DIR)/rules" && rsync -a "$(RULES_DIR)/" "$(BIN_DIR)/rules/"
	@if [ -d "$(MODELS_DIR)" ] && ls $(MODELS_DIR)/*.onnx >/dev/null 2>&1; then mkdir -p "$(BIN_DIR)/models" && rsync -a "$(MODELS_DIR)/" "$(BIN_DIR)/models/"; else echo "    warning: no ONNX in $(MODELS_DIR) — ML models not staged"; fi
	@echo "==> Installing on Linux"
	sudo $(BIN_DIR)/edr-installer-linux-amd64 install

install-darwin: build-darwin
	@echo "==> Staging rules next to installer (edr-installer copies from its directory)"
	@if [ ! -d "$(RULES_DIR)" ]; then echo "error: $(RULES_DIR) not found — cannot bundle baseline/YARA/Sigma rules"; exit 1; fi
	@mkdir -p "$(BIN_DIR)/rules" && rsync -a "$(RULES_DIR)/" "$(BIN_DIR)/rules/"
	@if [ -d "$(MODELS_DIR)" ] && ls $(MODELS_DIR)/*.onnx >/dev/null 2>&1; then mkdir -p "$(BIN_DIR)/models" && rsync -a "$(MODELS_DIR)/" "$(BIN_DIR)/models/"; else echo "    warning: no ONNX in $(MODELS_DIR) — ML models not staged"; fi
	@echo "==> Installing on macOS"
	@ARCH=$$(uname -m); \
	if [ "$$ARCH" = "arm64" ]; then \
		sudo $(BIN_DIR)/edr-installer-darwin-arm64 install 2>/dev/null || \
		echo "Note: installer not built for darwin/arm64, use scripts/install.sh"; \
	else \
		sudo $(BIN_DIR)/edr-installer-darwin-amd64 install 2>/dev/null || \
		echo "Note: installer not built for darwin/amd64, use scripts/install.sh"; \
	fi

# Single self-contained installer (agent + rules + models inside one binary via -tags embedbundle).
# Requires ./rules and ./models/*.onnx — slower/larger than install-darwin; use for releases or air-gap USB.
install-embedded: build-installer-embedded
	@echo "==> Installing from $(BIN_DIR)/edr-installer-embedded"
	sudo $(BIN_DIR)/edr-installer-embedded install

# ============================================================================
# Package targets (gov / enterprise — same distribution model as commercial EDR)
# See docs/ENTERPRISE_DEPLOYMENT.md for Linux .deb/.rpm, macOS .pkg + notarize,
# Windows zip + service install, MDM/GPO/Ansible, and single-file embedded installer.
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

# Self-contained offline package including all rules, models, ONNX runtime,
# config, and the systemd unit. Works fully without network access.
package-offline: build-all
	@echo "==> Creating offline self-contained package"
	@mkdir -p $(PACKAGE_DIR)/edr-offline/lib
	@cp $(BIN_DIR)/edr-agent-linux-amd64 $(PACKAGE_DIR)/edr-offline/edr-agent
	@cp $(BIN_DIR)/edrctl-linux-amd64 $(PACKAGE_DIR)/edr-offline/edrctl
	@cp $(BIN_DIR)/edr-installer-linux-amd64 $(PACKAGE_DIR)/edr-offline/edr-installer
	@cp -r configs $(PACKAGE_DIR)/edr-offline/configs
	@cp deploy/edr-agent.service $(PACKAGE_DIR)/edr-offline/
	@[ -d $(RULES_DIR) ] && cp -r $(RULES_DIR) $(PACKAGE_DIR)/edr-offline/rules || true
	@[ -d $(MODELS_DIR) ] && cp -r $(MODELS_DIR) $(PACKAGE_DIR)/edr-offline/models || true
	@# Bundle ONNX Runtime shared library if available
	@for lib in /usr/lib/libonnxruntime.so* /usr/local/lib/libonnxruntime.so* \
		/usr/lib/x86_64-linux-gnu/libonnxruntime.so* $(ONNXRUNTIME_LIB_PATH); do \
		[ -f "$$lib" ] && cp -P "$$lib" $(PACKAGE_DIR)/edr-offline/lib/ 2>/dev/null; \
	done; true
	@echo '#!/bin/bash' > $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'set -e' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'SCRIPT_DIR="$$(cd "$$(dirname "$$0")" && pwd)"' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'install -m 755 "$$SCRIPT_DIR/edr-agent" /usr/bin/' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'install -m 755 "$$SCRIPT_DIR/edrctl" /usr/bin/' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'id -u edr &>/dev/null || useradd -r -s /sbin/nologin edr' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'mkdir -p /etc/edr /var/lib/edr /var/log/edr /var/run/edr /usr/share/edr /usr/lib/edr' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'cp "$$SCRIPT_DIR"/configs/agent.yaml /etc/edr/' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo '[ -d "$$SCRIPT_DIR/rules" ] && cp -r "$$SCRIPT_DIR/rules" /usr/share/edr/' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo '[ -d "$$SCRIPT_DIR/models" ] && cp -r "$$SCRIPT_DIR/models" /usr/share/edr/' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo '# Install ONNX Runtime library if bundled' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'if ls "$$SCRIPT_DIR"/lib/libonnxruntime* 1>/dev/null 2>&1; then' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo '  cp -P "$$SCRIPT_DIR"/lib/libonnxruntime* /usr/lib/edr/' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo '  echo "/usr/lib/edr" > /etc/ld.so.conf.d/edr-onnx.conf' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo '  ldconfig' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'fi' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'cp "$$SCRIPT_DIR/edr-agent.service" /etc/systemd/system/' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'systemctl daemon-reload' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'systemctl enable edr-agent' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@echo 'echo "EDR agent installed. Start with: systemctl start edr-agent"' >> $(PACKAGE_DIR)/edr-offline/install.sh
	@chmod +x $(PACKAGE_DIR)/edr-offline/install.sh
	cd $(PACKAGE_DIR) && tar czf edr-$(VERSION)-offline-linux-amd64.tar.gz edr-offline/
	@rm -rf $(PACKAGE_DIR)/edr-offline
	@echo "==> Offline package: $(PACKAGE_DIR)/edr-$(VERSION)-offline-linux-amd64.tar.gz"
	@ls -lh $(PACKAGE_DIR)/edr-$(VERSION)-offline-linux-amd64.tar.gz

package-deb: build-linux
	@echo "==> Creating .deb package"
	./scripts/package_linux.sh

package-rpm: build-linux
	@echo "==> Creating .rpm package"
	EDR_SKIP_DEB=1 ./scripts/package_linux.sh

# One-folder macOS distribution: installer + agent + models + rules (sudo ./edr-installer install).
bundle-enterprise: build
	@./scripts/build-enterprise-bundle.sh

# Single self-contained edr-installer binary (models + rules embedded via go:embed).
# Requires ./models/*.onnx and ./rules/ — same as training release artifacts.
build-installer-embedded: build
	@test -d $(MODELS_DIR) && ls $(MODELS_DIR)/*.onnx >/dev/null 2>&1 || (echo "error: $(MODELS_DIR) must contain at least one .onnx"; exit 1)
	@test -d $(RULES_DIR) || (echo "error: $(RULES_DIR) missing"; exit 1)
	@test -f $(BIN_DIR)/edr-agent || (echo "error: run make build first (need $(BIN_DIR)/edr-agent)"; exit 1)
	@mkdir -p cmd/installer/bundle/bin
	rsync -a --delete $(MODELS_DIR)/ cmd/installer/bundle/models/
	rsync -a --delete $(RULES_DIR)/ cmd/installer/bundle/rules/
	cp $(BIN_DIR)/edr-agent cmd/installer/bundle/bin/
	-cp $(BIN_DIR)/edrctl cmd/installer/bundle/bin/
	GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build $(GOFLAGS) -tags embedbundle -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-installer-embedded ./cmd/installer
	@echo "==> $(BIN_DIR)/edr-installer-embedded — single file (agent+models+rules embedded). Run: sudo ./edr-installer-embedded install"

package-pkg: build-darwin
	@echo "==> Creating macOS .pkg installer (bundles ./models ONNX + configs/agent.yaml)"
	@echo "    Requires ./models/*.onnx — train first or set REQUIRE_MODELS=0"
	./scripts/package_macos.sh

# Consumer .pkg: embedded installer only (models inside bin/edr-installer-embedded) + first-run TCC wizard.
# Run on macOS: make build-installer-embedded && make package-pkg-consumer
package-pkg-consumer: build-installer-embedded
	@echo "==> Creating macOS consumer .pkg (embedded ML + first-run permissions)"
	@chmod +x ./scripts/package_macos_consumer.sh
	./scripts/package_macos_consumer.sh

# Notarize + staple a signed consumer .pkg (run on macOS; requires Apple Developer credentials).
# Usage: NOTARY_KEYCHAIN_PROFILE=edr make notarize-pkg-consumer
#    or: PKG=dist/edr-....consumer.pkg NOTARY_KEYCHAIN_PROFILE=edr make notarize-pkg-consumer
# Optional: SIGN_IDENTITY="Developer ID Installer: ..." to productsign before submit.
notarize-pkg-consumer:
	@chmod +x ./scripts/notarize_macos_pkg.sh
	@PKG="$(PKG)"; \
	if [ -z "$$PKG" ]; then PKG=$$(ls -t dist/*-consumer.pkg 2>/dev/null | head -1); fi; \
	if [ -z "$$PKG" ] || [ ! -f "$$PKG" ]; then \
		echo "No consumer pkg found. Run: make package-pkg-consumer"; \
		echo "Or set PKG=dist/your.pkg"; \
		exit 1; \
	fi; \
	./scripts/notarize_macos_pkg.sh "$$PKG"

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
	rm -rf cmd/installer/bundle/models cmd/installer/bundle/rules
	rm -f platform/linux/ebpf/*.o
	rm -f $(PROTO_OUT)/*.pb.go
	@echo "==> Clean complete"
