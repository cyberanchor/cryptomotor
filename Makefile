# cryptomotor — cross-platform build targets
#
# Usage:
#   make              Build and package for the current platform
#   make all          Build and package for Linux (amd64, arm64) and Windows (amd64)
#   make test         Run all tests with race detector
#   make bench        Run benchmarks
#   make clean        Remove build artifacts
#
# The resulting binary is:
#   - Statically linked (CGO_ENABLED=0)
#   - Stripped of symbols and DWARF (-s -w)
#   - No BuildID (-buildid=)
#   - No VCS metadata (-buildvcs=false)
#   - No file system paths (-trimpath)

BINARY     := cryptomotor
VERSION    := 3.1.0
CMD        := ./cmd/cryptomotor
DIST       := output

LDFLAGS    := -s -w -buildid=
GOFLAGS    := -trimpath -buildvcs=false
ENVFLAGS   := CGO_ENABLED=0

# Detect local OS and Architecture for the default build target
LOCAL_OS   := $(shell go env GOOS)
LOCAL_ARCH := $(shell go env GOARCH)
BIN_EXT    := $(if $(filter windows,$(LOCAL_OS)),.exe,)

.PHONY: build all test bench clean lint

# Default: build for current OS/arch.
build:
	@echo "Building $(BINARY) v$(VERSION) for $(LOCAL_OS)/$(LOCAL_ARCH)..."
	@mkdir -p $(DIST)
	@$(ENVFLAGS) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)$(BIN_EXT) $(CMD)
	@echo "Packaging into ZIP archive..."
	@zip -j -q $(DIST)/$(BINARY)_v$(VERSION)_$(LOCAL_OS)_$(LOCAL_ARCH).zip $(DIST)/$(BINARY)$(BIN_EXT) README.md
	@rm -f $(DIST)/$(BINARY)$(BIN_EXT)
	@echo "--- Build Successful ---"
	@ls -lh $(DIST)/$(BINARY)_v$(VERSION)_$(LOCAL_OS)_$(LOCAL_ARCH).zip
	@echo "--- SHA256 Checksum ---"
	@cd $(DIST) && sha256sum $(BINARY)_v$(VERSION)_$(LOCAL_OS)_$(LOCAL_ARCH).zip

# Cross-compile and package for release targets.
all: clean
	@echo "Cross-compiling $(BINARY) v$(VERSION) for release..."
	@mkdir -p $(DIST)
	
	@echo "Compiling for Linux (amd64)..."
	@$(ENVFLAGS) GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(CMD)
	@zip -j -q $(DIST)/$(BINARY)_v$(VERSION)_linux_amd64.zip $(DIST)/$(BINARY) README.md
	
	@echo "Compiling for Linux (arm64)..."
	@$(ENVFLAGS) GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(CMD)
	@zip -j -q $(DIST)/$(BINARY)_v$(VERSION)_linux_arm64.zip $(DIST)/$(BINARY) README.md
	
	@echo "Compiling for Windows (amd64)..."
	@$(ENVFLAGS) GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY).exe $(CMD)
	@zip -j -q $(DIST)/$(BINARY)_v$(VERSION)_windows_amd64.zip $(DIST)/$(BINARY).exe README.md
	
	@echo "Cleaning up raw binaries..."
	@rm -f $(DIST)/$(BINARY) $(DIST)/$(BINARY).exe
	
	@echo "--- Built release archives in $(DIST)/ ---"
	@ls -lh $(DIST)/
	@echo "--- SHA256 Checksums ---"
	@cd $(DIST) && sha256sum *.zip > sha256sums.txt
	@cat $(DIST)/sha256sums.txt
	@echo "✓ Release artifacts are ready! Upload the .zip files and sha256sums.txt to GitHub Releases."

# Run all tests with race detector enabled.
test:
	go test -race -count=1 -v ./...

# Run benchmarks.
bench:
	go test -bench=. -benchmem ./internal/crypto/

# Remove build artifacts.
clean:
	@echo "Cleaning $(DIST)/ directory..."
	@rm -rf $(DIST)

# Static analysis (requires golangci-lint).
lint:
	golangci-lint run ./...