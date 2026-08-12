# Developer entrypoint for dbsec. `make help` lists targets.
SHELL := /bin/bash
.PHONY: help build release run test e2e e2e-vault fuzz fmt clippy check deny forge-sync cog-check pre-release clean

E2E_PG := dbsec-e2e-pg
E2E_BAO := dbsec-e2e-bao
E2E_BAO_IMAGE ?= openbao/openbao:latest

# Services already running are used as-is: set DBSEC_E2E_DSN (Postgres) or
# DBSEC_E2E_VAULT_ADDR (OpenBao) and that container is neither started nor
# torn down here.
define start_pg
if [ -n "$$DBSEC_E2E_DSN" ]; then \
	echo "e2e: using DBSEC_E2E_DSN=$$DBSEC_E2E_DSN"; \
else \
	docker rm -f $(E2E_PG) >/dev/null 2>&1 || true; \
	docker run -d --name $(E2E_PG) \
		-e POSTGRES_USER=dbsec -e POSTGRES_PASSWORD=dbsec -e POSTGRES_DB=dbsec \
		-p 5433:5432 postgres:17-alpine >/dev/null; \
	until docker exec $(E2E_PG) pg_isready -U dbsec >/dev/null 2>&1; do sleep 0.5; done; \
fi
endef

define stop_pg
if [ -z "$$DBSEC_E2E_DSN" ]; then docker rm -f $(E2E_PG) >/dev/null; fi
endef

# Dev-mode OpenBao with the Transit engine the DEK envelope needs. The key is
# created up front; index keys are minted by the proxy on first use.
define start_bao
if [ -n "$$DBSEC_E2E_VAULT_ADDR" ]; then \
	echo "e2e: using DBSEC_E2E_VAULT_ADDR=$$DBSEC_E2E_VAULT_ADDR"; \
else \
	docker rm -f $(E2E_BAO) >/dev/null 2>&1 || true; \
	docker run -d --name $(E2E_BAO) --cap-add=IPC_LOCK \
		-e BAO_DEV_ROOT_TOKEN_ID=root -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
		-p 8200:8200 $(E2E_BAO_IMAGE) >/dev/null; \
	until docker exec -e BAO_ADDR=http://127.0.0.1:8200 $(E2E_BAO) \
		bao status >/dev/null 2>&1; do sleep 0.5; done; \
	docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root $(E2E_BAO) \
		bao secrets enable transit >/dev/null; \
	docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=root $(E2E_BAO) \
		bao write -f transit/keys/dbsec >/dev/null; \
fi
endef

define stop_bao
if [ -z "$$DBSEC_E2E_VAULT_ADDR" ]; then docker rm -f $(E2E_BAO) >/dev/null; fi
endef

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

# Set DBSEC_E2E_STRICT_DRIVERS=1 to fail rather than skip when psycopg is not
# installed (pip install 'psycopg[binary]' psycopg2-binary).
e2e: ## Driver matrix (tokio-postgres, sqlx, psycopg) against dockerized Postgres
	@$(call start_pg)
	cargo test -p dbsec --test e2e --test e2e_sqlx --test e2e_psycopg -- --ignored --nocapture; \
		status=$$?; $(call stop_pg); exit $$status

e2e-vault: ## Vault/OpenBao key source against a live dev-mode OpenBao
	@$(call start_pg)
	@$(call start_bao)
	cargo test -p dbsec --test e2e_vault -- --ignored --nocapture; \
		status=$$?; $(call stop_bao); $(call stop_pg); exit $$status

fuzz: ## Smoke-run each fuzz target for 30s (needs nightly + cargo-fuzz)
	cd fuzz && cargo +nightly fuzz run pgwire -- -max_total_time=30
	cd fuzz && cargo +nightly fuzz run envelope -- -max_total_time=30
	cd fuzz && cargo +nightly fuzz run transform -- -max_total_time=30

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

# Deliberate divergence is recorded as a waiver rather than exempting the file:
# `FORGE_SYNC_REASON='...' ./scripts/forge-sync-check.sh --update`.
forge-sync: ## Check the configs copied from forge against the tag CI pins
	./scripts/forge-sync-check.sh

cog-check: ## Validate conventional commits since last tag + dry-run the version bump
	@command -v cog >/dev/null || { echo "cog not found — install with: brew install cocogitto"; exit 1; }
	@if git describe --tags --abbrev=0 >/dev/null 2>&1; then cog check --from-latest-tag; \
	else echo "no tags yet — skipping cog check (bump dry-run still parses commits)"; fi
	cog bump --auto --dry-run

pre-release: check deny forge-sync cog-check ## Everything CI will run, locally

clean: ## Remove build artifacts
	cargo clean
