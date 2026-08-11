# Developer entrypoint for dbsec. `make help` lists targets.
SHELL := /bin/bash
.PHONY: help build release run test e2e fuzz fmt clippy check deny cog-check pre-release clean

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

e2e: ## Driver integration suite against dockerized Postgres (needs docker)
	@docker rm -f dbsec-e2e-pg >/dev/null 2>&1 || true
	docker run -d --name dbsec-e2e-pg \
		-e POSTGRES_USER=dbsec -e POSTGRES_PASSWORD=dbsec -e POSTGRES_DB=dbsec \
		-p 5433:5432 postgres:17-alpine >/dev/null
	@until docker exec dbsec-e2e-pg pg_isready -U dbsec >/dev/null 2>&1; do sleep 0.5; done
	cargo test -p dbsec --test e2e -- --ignored --nocapture; \
		status=$$?; docker rm -f dbsec-e2e-pg >/dev/null; exit $$status

fuzz: ## Smoke-run each fuzz target for 30s (needs nightly + cargo-fuzz)
	cd fuzz && cargo +nightly fuzz run pgwire -- -max_total_time=30
	cd fuzz && cargo +nightly fuzz run envelope -- -max_total_time=30

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
