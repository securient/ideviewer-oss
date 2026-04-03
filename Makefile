VERSION ?= $(shell grep 'var Version' internal/version/version.go | cut -d'"' -f2)
LDFLAGS := -s -w -X github.com/securient/ideviewer-oss/internal/version.Version=$(VERSION)
BINARY := ideviewer

.PHONY: build build-all test clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ideviewer/

build-all: build-linux-amd64 build-linux-arm64 build-darwin-arm64 build-windows-amd64

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/ideviewer/

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/ideviewer/

build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 ./cmd/ideviewer/

build-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/ideviewer/

test:
	go test -race ./...

clean:
	rm -f $(BINARY)
	rm -rf dist/
