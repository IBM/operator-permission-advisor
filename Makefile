SHELL := /bin/bash
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
GOPATH?=$(go env GOPATH)


BINARY=opa

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -w $(GOFMT_FILES)

.PHONY: test
test:
	go test -v ./...

.PHONY: generate
generate:
	go generate

.PHONY: install
install: generate vet
	CGO_ENABLED=1 go install -tags "json1"

.PHONY: build
build: generate fmt vet
	CGO_ENABLED=1 go build -o "./bin/$(BINARY)" -tags "json1"
