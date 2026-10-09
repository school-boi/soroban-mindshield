CARGO ?= cargo
TARGET := wasm32v1-none
WASM := target/$(TARGET)/release/mindshield.wasm

.PHONY: help test lint fmt wasm clean

help:
	@echo "make test   - run the contract test suite"
	@echo "make lint   - clippy with warnings denied"
	@echo "make fmt    - format the workspace"
	@echo "make wasm   - build the deployable wasm artifact"

test:
	$(CARGO) test

lint:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

# Soroban SDK 27 requires the wasm32v1-none target (Rust 1.84+).
wasm:
	rustup target add $(TARGET)
	$(CARGO) build --target $(TARGET) --release
	@ls -l $(WASM)

clean:
	$(CARGO) clean
