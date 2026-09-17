# [DAN] BRIDGE DASHBOARD — developer & CI conveniences.
# Node standard library only; no build step, no runtime dependencies. Every target below drives the
# real CLI and the real loopback hub — nothing is mocked. Portable to the make that ships with macOS
# (GNU Make 3.81): the multi-step targets live in scripts/ so no .ONESHELL is required.

.DEFAULT_GOAL := help

.PHONY: help test attack demo bench

help: ## Show this help.
	@echo "[DAN] BRIDGE DASHBOARD — make targets:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'
	@echo

test: ## Run the full test suite (Node's built-in runner; no install needed).
	node --test test/*.test.mjs

attack: ## Run ONLY the adversarial / security-regression tests and prove they hold.
	@echo "=================================================================="
	@echo " ATTACK SUITE — the hub under hostile input. All of these must hold:"
	@echo "   unauth 401 . identity-spoof 403 . out-of-scope 403 . replay 409"
	@echo "   unsigned 400 . bad-signature 403 . unauth-flood 429 . oversize 413"
	@echo "=================================================================="
	node --test test/server.test.mjs test/hardening-regression.test.mjs

demo: ## End-to-end demo in a temp dir: register -> boot -> sign -> POST -> read back.
	@bash scripts/demo.sh

bench: ## Post/read throughput over loopback (override count with BENCH_N=...).
	@BENCH_N=$(BENCH_N) bash scripts/bench.sh
