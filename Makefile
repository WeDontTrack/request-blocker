GO      ?= go
GOOS    ?= linux
GOARCH  ?= amd64
BINDIR  ?= bin
DESTDIR ?=

PREFIX_BIN  ?= /usr/local/bin
PREFIX_SBIN ?= /usr/local/sbin

.PHONY: all build fmt fmt-check vet lint test check clean install uninstall

all: build

## build: cross-compile both binaries (defaults to linux/amd64)
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -o $(BINDIR)/webblock  ./cmd/webblock
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -o $(BINDIR)/webblockd ./cmd/webblockd

## fmt: format all Go sources
fmt:
	$(GO) fmt ./...

## fmt-check: fail if any file is not gofmt-clean (used in CI)
fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

## vet: run go vet
vet:
	$(GO) vet ./...

## lint: run golangci-lint (install: https://golangci-lint.run)
lint:
	golangci-lint run

## test: run unit + daemon e2e tests (does not touch the real firewall)
test:
	$(GO) test ./...

## check: run all standards gates (what CI runs)
check: fmt-check vet lint test

## install: install binaries + systemd unit (run as root on the target Linux host)
install: build
	install -d $(DESTDIR)$(PREFIX_BIN) $(DESTDIR)$(PREFIX_SBIN)
	install -m 0755 $(BINDIR)/webblock  $(DESTDIR)$(PREFIX_BIN)/webblock
	install -m 0755 $(BINDIR)/webblockd $(DESTDIR)$(PREFIX_SBIN)/webblockd
	install -d $(DESTDIR)/etc/systemd/system
	install -m 0644 deploy/webblockd.service $(DESTDIR)/etc/systemd/system/webblockd.service
	@echo
	@echo "Installed. Enable the service with:"
	@echo "  systemctl daemon-reload && systemctl enable --now webblockd"

## uninstall: remove firewall rules, service, and binaries (run as root)
uninstall:
	-systemctl disable --now webblockd
	-$(PREFIX_SBIN)/webblockd -teardown
	-rm -f $(PREFIX_BIN)/webblock $(PREFIX_SBIN)/webblockd /etc/systemd/system/webblockd.service
	-systemctl daemon-reload

## clean: remove build artifacts
clean:
	rm -rf $(BINDIR)
