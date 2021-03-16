PREFIX ?= /usr/local
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

GIT_REVISION := $(shell git rev-list -1 HEAD | head -c 7)

MAKEFLAGS += --no-print-directory

.PHONY: all clean install uninstall generate-version-and-build wireguard-go wg tests gotest

all: generate-version-and-build

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go wg

wireguard-go:
	go build -v -o wireguard-go
wg:
	go build -v -ldflags "-X main.gitRevision=$(GIT_REVISION)" -o wg ./cmd/wgctrl/main.go

install: wireguard-go wg
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "wireguard-go" "$(DESTDIR)$(BINDIR)/wireguard-go"
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "wg" "$(DESTDIR)$(BINDIR)/wg"

uninstall:
	rm -rf "$(DESTDIR)$(BINDIR)/wireguard-go"
	rm -rf "$(DESTDIR)$(BINDIR)/wg"

gotest:
	go test -mod vendor -count=1 ./...

tests:
	sudo tests/netns.sh ./wireguard-go ./wg

clean:
	rm -f wireguard-go
	rm -f wg
