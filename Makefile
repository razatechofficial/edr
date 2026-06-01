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
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GOFLAGS := -trimpath
LDFLAGS := -s -w \
	-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE) \
	-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.Commit=$(COMMIT)

BIN_DIR     := bin
PROTO_DIR   := proto
PROTO_OUT   := pkg/protocol
GOPATH_BIN  := $(shell go env GOPATH 2>/dev/null)/bin
RULES_DIR   := rules
MODELS_DIR  := models
PACKAGE_DIR := dist
HOST_OS := $(shell uname -s)
ifeq ($(HOST_OS),Linux)
# YARA via go-yara needs libyara at link time; default off when pkg-config cannot find it
# (e.g. make build-all on GitHub ubuntu-latest). Release/test jobs install libyara-dev and
# pass LINUX_CGO=1 explicitly.
ifeq ($(shell pkg-config --exists yara 2>/dev/null && echo 1),1)
LINUX_CGO ?= 1
else
LINUX_CGO ?= 0
endif
else
LINUX_CGO ?= 0
endif
# linux/arm64 agent with CGO requires an aarch64 toolchain; on linux/amd64 CI
# hosts cross-compilation fails with CGO_ENABLED=1. Native arm64 hosts keep YARA.
LINUX_CGO_ARM64 ?= $(if $(filter arm64,$(shell go env GOHOSTARCH)),$(LINUX_CGO),0)
# dist/darwin-* agents need native macOS toolchains for ESF+YARA CGO; never force
# CGO when cross-compiling from Linux/Windows (e.g. make build-all on GitHub).
ifeq ($(HOST_OS),Darwin)
DARWIN_DIST_CGO := 1
else
DARWIN_DIST_CGO := 0
endif
# Windows: default off on non-Linux (hosted Windows has mingw without YARA deps).
# Linux cross-builds may enable when mingw is present; override with WINDOWS_CGO=1/0.
WINDOWS_CGO := 0
ifeq ($(HOST_OS),Linux)
ifneq ($(shell command -v x86_64-w64-mingw32-gcc 2>/dev/null),)
WINDOWS_CGO := 1
endif
endif

CLANG      ?= clang
define find_clang
$(shell \
  if [ -n "$(CLANG)" ] && $(CLANG) --target=bpf -print-targets 2>&1 | grep -q bpf; then \
    echo "$(CLANG)"; \
  elif [ -x "/opt/homebrew/opt/llvm/bin/clang" ] && \
       /opt/homebrew/opt/llvm/bin/clang --target=bpf -print-targets 2>&1 | grep -q bpf; then \
    echo "/opt/homebrew/opt/llvm/bin/clang"; \
  elif [ -x "/usr/local/opt/llvm/bin/clang" ] && \
       /usr/local/opt/llvm/bin/clang --target=bpf -print-targets 2>&1 | grep -q bpf; then \
    echo "/usr/local/opt/llvm/bin/clang"; \
  elif command -v clang-17 >/dev/null 2>&1; then \
    echo "clang-17"; \
  elif command -v clang-16 >/dev/null 2>&1; then \
    echo "clang-16"; \
  elif command -v clang >/dev/null 2>&1 && \
       clang --target=bpf -print-targets 2>&1 | grep -q bpf; then \
    echo "clang"; \
  else \
    echo ""; \
  fi)
endef
CLANG_BPF ?= $(call find_clang)
ifeq ($(CLANG_BPF),)
CLANG_BPF := clang-16
endif
BPF_ARCH   := $(shell uname -m 2>/dev/null | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' || echo "x86")
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Wall -Werror -Wno-missing-declarations
LIBBPF_SYSTEM := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_VENDOR := -Iplatform/linux/ebpf/libbpf
LIBBPF_DEFAULT := -I/usr/include
BPF_INCLUDES := $(LIBBPF_SYSTEM) $(LIBBPF_VENDOR) $(LIBBPF_DEFAULT) -Iplatform/linux/ebpf

.PHONY: build-linux build-darwin build-darwin-production build-windows build-darwin-nosec build-all
.PHONY: bundle-enterprise build-installer-embedded
.PHONY: ebpf ebpf-link ebpf-install bpf-version-check proto
.PHONY: test test-collector test-detection test-response test-race test-ci test-ci-race monitoring-soak test-coverage local-validate-monitoring diagnose-esf
.PHONY: run-agent run-agent-ml test-edr-macos-lab
.PHONY: test-bench
.PHONY: vulncheck
.PHONY: rules-update intel-update models-update release-assets
.PHONY: models-bootstrap models-validate models-sign
.PHONY: train-all train-pe train-behavior train-network train-ransomware
.PHONY: install-linux install-darwin install-embedded edrctl
.PHONY: package package-deb package-rpm package-sqa-kali package-pkg package-pkg-consumer notarize-pkg-consumer package-msi clean fmt lint vet

# ============================================================================
# Build targets
# ============================================================================

build-linux:
	@echo "==> Building Linux amd64 binaries"
	CGO_ENABLED=$(LINUX_CGO) GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent-linux-amd64 ./cmd/agent
	CGO_ENABLED=$(LINUX_CGO) GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-installer-linux-amd64 ./cmd/installer
	CGO_ENABLED=$(LINUX_CGO) GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl-linux-amd64 ./cmd/cli
	@mkdir -p dist/linux-amd64 dist/linux-arm64
	CGO_ENABLED=$(LINUX_CGO) GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/linux-amd64/edr-agent ./cmd/agent
	CGO_ENABLED=$(LINUX_CGO_ARM64) GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/linux-arm64/edr-agent ./cmd/agent

build-darwin:
	@echo "==> Building macOS binaries"
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent-darwin-amd64 ./cmd/agent
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent-darwin-arm64 ./cmd/agent
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-installer-darwin-amd64 ./cmd/installer
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-installer-darwin-arm64 ./cmd/installer
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl-darwin-amd64 ./cmd/cli
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl-darwin-arm64 ./cmd/cli
	@mkdir -p dist/darwin-amd64 dist/darwin-arm64
	CGO_ENABLED=$(DARWIN_DIST_CGO) GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/darwin-amd64/edr-agent ./cmd/agent
	CGO_ENABLED=$(DARWIN_DIST_CGO) GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/darwin-arm64/edr-agent ./cmd/agent

build-windows:
	@echo "==> Building Windows amd64 binaries"
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-agent-windows-amd64.exe ./cmd/agent
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edrctl-windows-amd64.exe ./cmd/cli
	@mkdir -p dist/windows-amd64
ifeq ($(WINDOWS_CGO),1)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/windows-amd64/edr-agent.exe ./cmd/agent
else
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/windows-amd64/edr-agent.exe ./cmd/agent
endif
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/windows-amd64/edrctl.exe ./cmd/cli

build-darwin-production:
	@bash scripts/ci/build_macos_production.sh

build-darwin-nosec:
	@echo "==> Building macOS arm64 nosec variant"
	@mkdir -p dist/darwin-arm64-nosec
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -tags nosec $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/darwin-arm64-nosec/edr-agent ./cmd/agent

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

build-controlplane:
	@echo "==> Building edr-controlplane"
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/edr-controlplane ./cmd/controlplane

deploy-controlplane: build-controlplane
	@bash scripts/deploy/install_controlplane.sh "$(BIN_DIR)/edr-controlplane"

stage-controlplane-policy:
	@bash scripts/deploy/stage_controlplane_policy.sh $(POLICY_DIR)

verify-controlplane-policy:
	@bash scripts/pilot/verify_controlplane_policy.sh $(HOST)

export-controlplane-env:
	@bash scripts/deploy/export_controlplane_env.sh $(ENV_FILE)

enable-controlplane-tls:
	@bash scripts/deploy/enable_controlplane_tls.sh $(HOST)

generate-controlplane-tls:
	@bash scripts/deploy/generate_controlplane_tls.sh $(TLS_DIR)

prepare-windows-signing-secrets:
	@bash scripts/ci/prepare_github_windows_signing_secrets.sh $(PFX)

run-fleet-pilot:
	@bash scripts/pilot/run_fleet_pilot.sh $(HOST) $(EXPECTED)

verify-detection-pilot:
	@bash scripts/pilot/verify_detection_pipeline.sh $(HOST)

verify-agent-enrollment:
	@bash scripts/pilot/verify_agent_enrollment.sh $(HOST) $(AGENT_ID)

verify-detection-pilot-windows:
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/pilot/verify_detection_pipeline.ps1 $(HOST)

verify-release-packages:
	@bash scripts/ci/verify_release_packages.sh $(DIST)

verify-post-install:
	@bash scripts/pilot/verify_installed_agent.sh $(HOST)

run-endpoint-pilot:
	@EDR_PILOT_VERIFY_DETECTION=$(DETECT) bash scripts/pilot/run_endpoint_pilot.sh $(HOST)

check-prod-release:
	@bash scripts/pilot/check_prod_release.sh $(BRANCH)

wait-for-prod-release:
	@bash scripts/pilot/wait_for_prod_release.sh $(BRANCH)

prepare-fleet-rollout:
	@EDR_ROLLOUT_WAIT_RELEASE=$(WAIT) bash scripts/pilot/prepare_fleet_rollout.sh $(TAG) $(OUT)

distribute-agent-tls:
	@bash scripts/deploy/distribute_agent_tls.sh $(TLS_SRC) $(HOST) $(PLATFORM)

run-prod-rollout:
	@bash scripts/pilot/run_prod_rollout.sh $(HOST) $(EXPECTED)

fetch-release-artifacts:
	@bash scripts/pilot/fetch_release_artifacts.sh $(TAG) $(DIST)

rollout-status:
	@bash scripts/pilot/rollout_status.sh $(HOST) $(EXPECTED)

list-fleet-endpoints:
	@bash scripts/pilot/list_fleet_endpoints.sh $(HOST)

preflight-rollout:
	@bash scripts/pilot/preflight_rollout.sh $(HOST)

verify-fleet-rollout:
	@bash scripts/pilot/verify_fleet_rollout.sh $(HOST) $(EXPECTED)

stage-fleet-rollout-bundle:
	@bash scripts/pilot/stage_fleet_rollout_bundle.sh $(OUT)

backup-controlplane:
	@bash scripts/deploy/backup_controlplane.sh $(OUT)

restore-controlplane:
	@EDR_RESTORE_CONFIRM=1 bash scripts/deploy/restore_controlplane.sh $(ARCHIVE)

validate-rollout:
	@bash scripts/pilot/run_rollout_validation.sh $(HOST) $(EXPECTED)

upgrade-linux-agent:
	@bash scripts/pilot/upgrade_linux_agent.sh $(PKG)

upgrade-macos-agent:
	@bash scripts/pilot/upgrade_macos_agent.sh $(PKG)

upgrade-windows-agent:
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/pilot/upgrade_windows_agent.ps1 $(PKG)

.PHONY: build-controlplane deploy-controlplane stage-controlplane-policy verify-controlplane-policy export-controlplane-env prepare-windows-signing-secrets enable-controlplane-tls generate-controlplane-tls run-fleet-pilot verify-detection-pilot verify-agent-enrollment verify-detection-pilot-windows verify-release-packages verify-post-install run-endpoint-pilot check-prod-release wait-for-prod-release prepare-fleet-rollout distribute-agent-tls run-prod-rollout fetch-release-artifacts rollout-status list-fleet-endpoints preflight-rollout verify-fleet-rollout stage-fleet-rollout-bundle backup-controlplane restore-controlplane validate-rollout upgrade-linux-agent upgrade-macos-agent upgrade-windows-agent

# ============================================================================
# eBPF targets (Linux only)
# Sources include lsm_fim.c (LSM hooks); requires CONFIG_BPF_LSM for attach.
# ============================================================================

EBPF_SRC     := $(wildcard platform/linux/ebpf/*.c)
EBPF_OBJ     := $(EBPF_SRC:.c=.o)
EBPF_MERGED  := platform/linux/ebpf/edr.bpf.o
EBPF_INSTALL := /var/lib/edr/bpf/edr.bpf.o
EBPF_VER_INSTALL := /var/lib/edr/bpf/edr.bpf.version
VMLINUX_H    := platform/linux/ebpf/vmlinux.h
VMLINUX_FALLBACK := platform/linux/ebpf/vmlinux_fallback.h
LLVM_LINK    ?= llvm-link
BPFTOOL      ?= bpftool

$(VMLINUX_H):
	@if command -v $(BPFTOOL) >/dev/null 2>&1 && [ -f /sys/kernel/btf/vmlinux ] && [ "$${EDR_VMLINUX_FALLBACK:-0}" != "1" ]; then \
		echo "==> Generating vmlinux.h from kernel BTF"; \
		if $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); then \
			:; \
		else \
			echo "bpftool dump failed; using fallback vmlinux.h"; \
			cp $(VMLINUX_FALLBACK) $(VMLINUX_H); \
		fi; \
	else \
		echo "BTF not available or fallback forced; using fallback vmlinux.h"; \
		cp $(VMLINUX_FALLBACK) $(VMLINUX_H); \
	fi

ebpf: $(VMLINUX_H) $(EBPF_OBJ)
	@if [ -z "$(CLANG_BPF)" ]; then \
		echo "No clang with BPF backend found. Install llvm/clang or set CLANG=/path/to/bpf-capable-clang"; \
		exit 1; \
	fi
	@echo "==> eBPF programs compiled"

platform/linux/ebpf/%.o: platform/linux/ebpf/%.c platform/linux/ebpf/common.h $(VMLINUX_H)
	@BPF_CLANG="$(CLANG_BPF)"; \
	if [ -z "$$BPF_CLANG" ]; then BPF_CLANG="$${CLANG:-clang-16}"; fi; \
	if ! command -v "$$BPF_CLANG" >/dev/null 2>&1; then BPF_CLANG=clang; fi; \
	"$$BPF_CLANG" $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

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
	@cp internal/kernel/ebpf_expected_version.txt platform/linux/ebpf/edr.bpf.version
	@echo "==> Synced platform/linux/ebpf/edr.bpf.version from internal/kernel/ebpf_expected_version.txt"

ebpf-install: ebpf-link
	@echo "==> Installing eBPF bytecode to $(EBPF_INSTALL)"
	@sudo mkdir -p $(dir $(EBPF_INSTALL))
	@sudo install -m 644 $(EBPF_MERGED) $(EBPF_INSTALL)
	@sudo install -m 644 internal/kernel/ebpf_expected_version.txt $(EBPF_VER_INSTALL)
	@echo "==> Installed: $(EBPF_INSTALL) and $(EBPF_VER_INSTALL)"

# Verify in-tree BPF version sidecar matches internal/kernel/ebpf_expected_version.txt
# when platform/linux/ebpf/edr.bpf.o exists (run make ebpf-link first).
bpf-version-check:
	@bash scripts/ci/verify-bpf-version.sh

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

GO_TEST_PKGS := $(shell go list ./... 2>/dev/null | grep -v '/temp/' || true)

test:
	@echo "==> Running all tests"
	go test $$(go list ./... | grep -v '/temp/') -count=1 -timeout 600s

test-ci: test

test-ci-race:
	@echo "==> Running CI race tests"
	go test $$(go list ./... | grep -v '/temp/') -race -count=1 -timeout 300s

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
	go test $$(go list ./... | grep -v '/temp/') -race -count=1 -timeout 300s

# Longer race pass on the monitoring stack (avoids `go test ./...` which may include non-repo trees).
monitoring-soak:
	@echo "==> Monitoring layer soak (collector + agent CLI, race, nosec)"
	EDR_SOAK_MONITORING=1 go test -race -count=1 -timeout 300s -tags nosec ./internal/collector/... ./cmd/agent/...

local-validate-monitoring:
	@echo "==> Local monitoring validation (auto fallback to nosec when ESF unavailable)"
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		ESF_SDK="$$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)/System/Library/Frameworks/EndpointSecurity.framework"; \
		ESF_SYS="/System/Library/Frameworks/EndpointSecurity.framework"; \
		ESF_OK=0; \
		if [ -d "$$ESF_SYS" ] || [ -d "$$ESF_SDK" ]; then ESF_OK=1; fi; \
		if [ $$ESF_OK -eq 1 ] && [ "$${CGO_ENABLED:-1}" != "0" ]; then \
			echo "    ESF framework detected; running full local monitoring validation"; \
			go test ./internal/collector/... ./internal/kernel/... ./cmd/agent/... -count=1 -timeout 180s; \
			go test -tags nosec ./internal/kernel/... ./internal/collector/... -run 'TestReattach|TestWatchdog|TestNetworkExtension|TestESFRevocation|TestLinuxFileDeduper|TestEffectiveLogTargets|TestLogTargetsCollectorHealthRows|TestPersistInventoryRecordsAndMaybeDelta' -count=1; \
		else \
			if [ $$ESF_OK -ne 1 ]; then \
				echo "    reason: EndpointSecurity.framework missing (checked $$ESF_SYS and $$ESF_SDK)"; \
			fi; \
			if [ "$${CGO_ENABLED:-1}" = "0" ]; then \
				echo "    reason: CGO_ENABLED=0"; \
			fi; \
			echo "    using nosec fallback"; \
			go test -tags nosec ./internal/collector/... ./internal/kernel/... ./cmd/agent/... -count=1 -timeout 180s; \
			go test -tags nosec ./internal/kernel/... ./internal/collector/... -run 'TestReattach|TestWatchdog|TestNetworkExtension|TestESFRevocation|TestLinuxFileDeduper|TestEffectiveLogTargets|TestLogTargetsCollectorHealthRows|TestPersistInventoryRecordsAndMaybeDelta' -count=1; \
		fi; \
	else \
		echo "    non-Darwin host; using nosec validation path"; \
		go test -tags nosec ./internal/collector/... ./internal/kernel/... ./cmd/agent/... -count=1 -timeout 180s; \
		go test -tags nosec ./internal/kernel/... ./internal/collector/... -run 'TestReattach|TestWatchdog|TestNetworkExtension|TestESFRevocation|TestLinuxFileDeduper|TestEffectiveLogTargets|TestLogTargetsCollectorHealthRows|TestPersistInventoryRecordsAndMaybeDelta' -count=1; \
	fi

diagnose-esf:
	@echo "==> Diagnose EndpointSecurity toolchain readiness"
	@if [ "$$(uname -s)" != "Darwin" ]; then \
		echo "host_os=$$(uname -s)"; \
		echo "result=non-darwin"; \
		echo "recommended_mode=nosec"; \
		exit 0; \
	fi
	@set -e; \
	SDKROOT="$$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"; \
	echo "sdkroot=$$SDKROOT"; \
	echo "cgo_enabled=$${CGO_ENABLED:-unset}"; \
	PROBE_C="$${TMPDIR:-/tmp}/es_probe.c"; \
	PROBE_BIN="$${TMPDIR:-/tmp}/es_probe"; \
	printf '%s\n' '#include <EndpointSecurity/EndpointSecurity.h>' 'int main(void) { return 0; }' >"$$PROBE_C"; \
	HDR_OK=0; \
	LINK_OK=0; \
	if xcrun --sdk macosx clang -isysroot "$$SDKROOT" -fsyntax-only "$$PROBE_C" >/dev/null 2>&1; then \
		HDR_OK=1; \
	fi; \
	if xcrun --sdk macosx clang -isysroot "$$SDKROOT" "$$PROBE_C" -framework EndpointSecurity -o "$$PROBE_BIN" >/dev/null 2>&1; then \
		LINK_OK=1; \
	fi; \
	echo "header_probe=$$HDR_OK"; \
	echo "link_probe=$$LINK_OK"; \
	if [ $$LINK_OK -eq 1 ] && [ "$${CGO_ENABLED:-1}" != "0" ]; then \
		echo "result=esf_link_ready"; \
		echo "recommended_mode=full"; \
	else \
		echo "result=esf_link_unavailable"; \
		if [ $$HDR_OK -eq 1 ] && [ $$LINK_OK -ne 1 ]; then \
			echo "reason=headers_present_but_framework_unlinkable"; \
		fi; \
		if [ "$${CGO_ENABLED:-1}" = "0" ]; then \
			echo "reason=cgo_disabled"; \
		fi; \
		echo "recommended_mode=nosec"; \
	fi; \
	rm -f "$$PROBE_C" "$$PROBE_BIN"

test-coverage:
	@echo "==> Running tests with coverage"
	go test $$(go list ./... | grep -v '/temp/') -coverprofile=coverage.out -covermode=atomic -timeout 600s
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
	@echo "IOC update complete (see rules/ioc/*.json and rules/ioc/*.csv)"

release-assets:
	@bash scripts/ci/prepare_release_assets.sh

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

package-sqa-kali:
	@chmod +x scripts/package_sqa_kali.sh scripts/sqa_simulations.sh
	./scripts/package_sqa_kali.sh

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
