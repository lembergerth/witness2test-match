# This file is part of witness2test-match,
# a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
# https://github.com/lembergerth/witness2test-match
#
# SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
#
# SPDX-License-Identifier: Apache-2.0

.PHONY: build clean test lint integration-test deps help

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
	@echo "  lint             : Run golangci-lint"
	@echo "  clean            : Remove build artifacts"
	@echo "  help             : Show this help message"
