SHELL := /bin/bash
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
GOPATH?=$(go env GOPATH)


BINARY=operator-permission-advisor

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -w $(GOFMT_FILES)

.PHONY: generate
generate:
	go generate

.PHONY: install
install: generate vet
	CGO_ENABLED=1 go install -tags "json1"

.PHONY: build
build: generate fmt vet
	CGO_ENABLED=1 go build -o "./bin/$(BINARY)" -tags "json1"

.PHONY: test
test: generate fmt vet
	cd pkg && go test ./...

.PHONY: release
release: test build
	tar -czf $(BINARY).tar.gz "./bin/$(BINARY)"
	shasum -a 256 $(BINARY).tar.gz > checksum.sha56