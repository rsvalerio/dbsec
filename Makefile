# Developer entrypoint for dbsec. `make help` lists targets.
SHELL := /bin/bash
.PHONY: help build release run test fmt clippy check deny cog-check pre-release clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Compile (debug)
	cargo build --all --all-features

release: ## Compile (release)
	cargo build --release --bin dbsec

run: ## Run the proxy
	cargo run --bin dbsec

test: ## Run the test suite
	cargo test --all --all-features

fmt: ## Format all crates
	cargo fmt --all

clippy: ## Lint, warnings as errors
	cargo clippy --all --all-features -- -D warnings

# `ops verify qa` derives each gate from the detected stack: for a Rust workspace it runs
# cargo fmt --check, clippy -D warnings, check, and test.
check: ## All QA gates via ops
	ops verify qa

deny: ## Dependency audit: licenses, advisories, bans (deny.toml)
	cargo deny check

cog-check: ## Validate conventional commits since last tag + dry-run the version bump
	@command -v cog >/dev/null || { echo "cog not found — install with: brew install cocogitto"; exit 1; }
	@if git describe --tags --abbrev=0 >/dev/null 2>&1; then cog check --from-latest-tag; \
	else echo "no tags yet — skipping cog check (bump dry-run still parses commits)"; fi
	cog bump --auto --dry-run

pre-release: check deny cog-check ## Everything CI will run, locally

clean: ## Remove build artifacts
	cargo clean
