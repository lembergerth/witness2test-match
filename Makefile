# This file is part of witness2test-match,
# a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
# https://github.com/lembergerth/witness2test-match
#
# SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
#
# SPDX-License-Identifier: Apache-2.0

.PHONY: build clean test lint integration-test archive-test deps help sv-comp-archive

GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_NAME=bin/witness2test-match

build:
	$(GOBUILD) -o $(BINARY_NAME) -v -ldflags="-X main.version=$(shell git describe --always --dirty 2>/dev/null || echo unknown)"

deps:
	$(GOCMD) mod tidy

test:
	$(GOTEST) -v ./...

integration-test: build
	./integration-test.sh

sv-comp-archive: build
	@set -eu; \
	version=$$($(BINARY_NAME) --version); \
	version=$${version##* }; \
	package="witness2test-match-$$version"; \
	archive="$$package.zip"; \
	staging=$$(mktemp -d); \
	trap 'rm -rf "$$staging"' EXIT HUP INT TERM; \
	mkdir -p "$$staging/$$package/bin"; \
	cp $(BINARY_NAME) "$$staging/$$package/bin/"; \
	cp -R smoketest.sh integration-test.sh integration REUSE.toml LICENSE LICENSES "$$staging/$$package/"; \
	cp README.adoc "$$staging/$$package/README"; \
	(cd "$$staging" && zip -qr "$$archive" "$$package"); \
	mv "$$staging/$$archive" "$$archive"; \
	echo "Created $$archive"

archive-test: sv-comp-archive
	python3 archive-test.py

lint:
	golangci-lint run

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

help:
	@echo "Available targets:"
	@echo "  build            : Build the project"
	@echo "  deps             : Download and verify dependencies"
	@echo "  test             : Run unit tests"
	@echo "  integration-test : Run integration tests"
	@echo "  archive-test     : Test the release archive (requires Python 3, zip, unzip)"
	@echo "  sv-comp-archive  : Package the executable for SV-COMP (requires zip)"
	@echo "  lint             : Run golangci-lint"
	@echo "  clean            : Remove build artifacts"
	@echo "  help             : Show this help message"
