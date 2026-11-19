# cryptomotor — build, test and release targets
#
#   make                      build and package for the current platform (output/)
#   make all                  release archives for linux/amd64, linux/arm64, windows/amd64
#                             plus output/sha256sums.txt
#   make test                 all tests (make test-short skips the 192 MiB stream test)
#   make race                 all tests under the race detector
#   make e2e [OLD=path]       end-to-end tests of the real binary (e2e/e2e.sh); OLD is an
#                             optional cryptomotor 3.1.0 binary for the compatibility checks
#   make check                gofmt, go vet (Linux and Windows), go mod verify
#   make vulncheck            govulncheck
#   make verify-reproducible  build the release twice (second time with an empty cache)
#                             and compare the archives
#   make version | bench | clean | lint
#
# Binaries are static (CGO_ENABLED=0), stripped of symbols and DWARF (-s -w),
# carry no build ID, VCS stamp or file system path (-buildid= -buildvcs=false
# -trimpath): the same Go version produces the same bytes. Archives get fixed
# timestamps (SOURCE_DATE_EPOCH, by default the time of the last commit) and
# fixed file modes, so they are reproducible as well. Packaging needs zip.

BINARY      := cryptomotor
VERSION     := $(shell sed -n 's/^[[:space:]]*ProgramVersion = "\([^"]*\)".*/\1/p' internal/config/config.go)
CMD         := ./cmd/cryptomotor
DIST        := output
TARGETS     := linux/amd64 linux/arm64 windows/amd64
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.10.0
OLD         ?=

GO          ?= go
LDFLAGS     := -s -w -buildid=
BUILDFLAGS  := -trimpath -buildvcs=false
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 315532800)
export SOURCE_DATE_EPOCH

LOCAL_OS    := $(shell $(GO) env GOOS)
LOCAL_ARCH  := $(shell $(GO) env GOARCH)

.PHONY: build all package test test-short race e2e check vulncheck verify-reproducible version bench clean lint

# Default: build and package for the current OS/arch.
build:
	@$(MAKE) --no-print-directory package TARGET=$(LOCAL_OS)/$(LOCAL_ARCH)
	@ls -l $(DIST)/*.zip

# Cross-compile and package every release target.
all:
	@rm -rf $(DIST) && mkdir -p $(DIST)
	@for t in $(TARGETS); do $(MAKE) --no-print-directory package TARGET=$$t || exit 1; done
	@cd $(DIST) && sha256sum *.zip > sha256sums.txt && cat sha256sums.txt

# package TARGET=os/arch: one binary zipped with README, LICENSE and CHANGELOG.
package:
	@command -v zip >/dev/null || { echo "make: zip is required (dnf install zip / apt install zip)" >&2; exit 1; }
	@test -n "$(VERSION)" || { echo "make: cannot read ProgramVersion from internal/config/config.go" >&2; exit 1; }
	@set -eu; \
	os=$${TARGET%/*}; arch=$${TARGET#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
	name=$(BINARY)_v$(VERSION)_$${os}_$${arch}; stage=$(DIST)/.stage/$$name; \
	ts=$(SOURCE_DATE_EPOCH); [ "$$ts" -ge 315532800 ] || ts=315532800; \
	rm -rf "$$stage"; mkdir -p "$$stage"; \
	echo "Building $$name"; \
	CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o "$$stage/$(BINARY)$$ext" $(CMD); \
	cp README.md LICENSE CHANGELOG.md "$$stage/"; \
	chmod 0755 "$$stage/$(BINARY)$$ext"; chmod 0644 "$$stage/README.md" "$$stage/LICENSE" "$$stage/CHANGELOG.md"; \
	touch -d "@$$ts" "$$stage"/*; \
	rm -f "$(DIST)/$$name.zip"; \
	(cd "$$stage" && TZ=UTC zip -X -q "../../$$name.zip" "$(BINARY)$$ext" README.md LICENSE CHANGELOG.md); \
	rm -rf "$$stage"; rmdir "$(DIST)/.stage" 2>/dev/null || true

test:
	$(GO) test -count=1 ./...

test-short:
	$(GO) test -count=1 -short ./...

race:
	$(GO) test -race -count=1 -timeout 30m ./...

e2e:
	@set -eu; d=$$(mktemp -d); trap 'rm -rf "$$d"' EXIT; \
	CGO_ENABLED=0 $(GO) build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o "$$d/cryptomotor" $(CMD); \
	$(GO) build -o "$$d/cmcraft" ./e2e/cmcraft; \
	EXPECT_VERSION=$(VERSION) e2e/e2e.sh "$$d/cryptomotor" "$$d/cmcraft" "$$d/work" $(OLD)

check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "make: run gofmt -w on the files above" >&2; exit 1; }
	$(GO) vet ./...
	GOOS=windows $(GO) vet ./...
	$(GO) mod verify

vulncheck:
	$(GO) run $(GOVULNCHECK) ./...

verify-reproducible:
	@set -eu; a=$$(mktemp -d); b=$$(mktemp -d); c=$$(mktemp -d); trap 'chmod -R u+w "$$c"; rm -rf "$$a" "$$b" "$$c"' EXIT; \
	$(MAKE) --no-print-directory all DIST="$$a" >/dev/null; \
	GOCACHE="$$c" $(MAKE) --no-print-directory all DIST="$$b" >/dev/null; \
	if diff "$$a/sha256sums.txt" "$$b/sha256sums.txt"; then echo "reproducible: identical archives"; cat "$$a/sha256sums.txt"; \
	else echo "make: builds differ" >&2; exit 1; fi

version:
	@echo $(VERSION)

bench:
	$(GO) test -run '^$$' -bench=. -benchmem ./internal/crypto/

clean:
	rm -rf $(DIST)

# Static analysis (requires golangci-lint).
lint:
	golangci-lint run ./...
