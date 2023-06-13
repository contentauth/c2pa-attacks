# Makefile to aid with local development and testing
# This is not required for automated builds

ifeq ($(OS),Windows_NT)
	PLATFORM := win
else
	UNAME := $(shell uname)
    ifeq ($(UNAME),Linux)
        PLATFORM := linux
    endif
    ifeq ($(UNAME),Darwin)
        PLATFORM := mac
    endif
endif

check-format:
	cargo fmt -- --check

clippy:
	cargo clippy --all-features --all-targets -- -D warnings

test-local:
	cargo test --all-features

# Full local validation, build and test all features including wasm
# Run this before pushing a PR to pre-validate
test: check-format clippy test-local

fmt: 
	cargo +nightly fmt

# Creates a folder wtih c2pa-attacks bin, samples and readme
c2pa-attacks-package:
	rm -rf target/c2pa-attacks*
	mkdir -p target/c2pa-attacks
	mkdir -p target/c2pa-attacks/sample
	cp target/release/c2pa-attacks target/c2pa-attacks/c2pa-attacks
	cp README.md target/c2pa-attacks/README.md
	cp sample/* target/c2pa-attacks/sample
	cp CHANGELOG.md target/c2pa-attacks/CHANGELOG.md

# These are for building the c2pa-attacks release bin on various platforms
build-release-win:
	cargo build --release

build-release-mac-arm:
	rustup target add aarch64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=11.1 cargo build --target=aarch64-apple-darwin --release

build-release-mac-x86:
	rustup target add x86_64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=10.15 cargo build --target=x86_64-apple-darwin --release

build-release-mac-universal: build-release-mac-arm build-release-mac-x86
	lipo -create -output target/release/c2pa-attacks target/aarch64-apple-darwin/release/c2pa-attacks target/x86_64-apple-darwin/release/c2pa-attacks

build-release-linux:
	cargo build --release

# Builds and packages a zip for c2pa-attacks for each platform
ifeq ($(PLATFORM), mac)
release: build-release-mac-universal c2pa-attacks-package
	cd target && zip -r c2pa-attacks_mac_universal.zip c2pa-attacks && cd ..
endif
ifeq ($(PLATFORM), win)
release: build-release-win c2pa-attacks-package
	cd target && tar.exe -a -c -f c2pa-attacks_win_intel.zip c2pa-attacks && cd ..
endif
ifeq ($(PLATFORM), linux)
release: build-release-linux c2pa-attacks-package
	cd target && tar -czvf c2pa-attacks_linux_intel.tar.gz c2pa-attacks && cd ..
endif

