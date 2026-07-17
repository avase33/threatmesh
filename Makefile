.PHONY: up down test test-rust test-python test-go build-web demo verify

up:
	docker compose up --build

down:
	docker compose down

test: test-rust test-python test-go

test-rust:
	cd normalizer-rust && cargo test

test-python:
	cd detector-python && pip install -e ".[dev]" && pytest -q

test-go:
	cd gateway-go && go test ./...

build-web:
	cd frontend-ts && npm install && npm run build

# Offline: fit on baseline, score a mixed attack stream (no services needed).
demo:
	cd detector-python && python -m threatmesh_detector.cli demo

verify:
	python scripts/verify.py
