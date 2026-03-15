# asec-agent Makefile
# Requirements: clang, libbpf-dev, linux-headers-$(uname -r)
#   sudo apt-get install clang libbpf-dev linux-headers-$(uname -r)

ARCH   := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
MULTIARCH := $(shell dpkg-architecture -qDEB_BUILD_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)

BPF_CFLAGS := -O2 -g -Wall -Werror \
	-I/usr/include/$(MULTIARCH) \
	-I/usr/include

.PHONY: generate build clean install

## generate: compile eBPF C → Go (needs clang + libbpf-dev on Linux)
generate:
	export BPF_CFLAGS="$(BPF_CFLAGS)"; go generate ./probe/...

## build: compile the agent binary (static, no CGO)
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w" -o asec-agent .

## build-arm64: cross-compile for ARM64 (Raspberry Pi, ARM servers)
build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -ldflags="-s -w" -o asec-agent-arm64 .

## clean: remove compiled artifacts
clean:
	rm -f asec-agent asec-agent-arm64
	rm -f probe/*_bpf*.go probe/*.o

## install: install agent + systemd unit
install: build
	sudo cp asec-agent /usr/local/bin/asec-agent
	sudo cp agent.yaml.example /etc/asec-agent.yaml
	sudo cp systemd/asec-agent.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable asec-agent

## docker-build: build inside Ubuntu 22.04 container (for non-Linux hosts)
docker-build:
	docker run --rm -v $(PWD):/src -w /src ubuntu:22.04 bash -c \
		"apt-get update -q && apt-get install -y -q \
		  golang clang libbpf-dev linux-headers-generic make && \
		 make generate build"
