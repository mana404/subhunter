BINARY=subhunter
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"
BUILD_DIR=./build

.PHONY: all build clean install test lint cross

all: build

build:
	@echo "[*] Building $(BINARY) $(VERSION)..."
	go build $(LDFLAGS) -o $(BINARY) ./cmd/
	@echo "[+] Binary: ./$(BINARY)"

install: build
	@echo "[*] Installing to /usr/local/bin/..."
	sudo mv $(BINARY) /usr/local/bin/$(BINARY)
	@echo "[+] Installed! Run: subhunter --help"

cross:
	@echo "[*] Cross-compiling for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64   ./cmd/
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64   ./cmd/
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  ./cmd/
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  ./cmd/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./cmd/
	@echo "[+] Binaries in $(BUILD_DIR)/"

test:
	go test ./... -v -timeout 60s

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
	rm -rf $(BUILD_DIR)

run-example:
	go run ./cmd/ -d hackerone.com -v -o results.txt