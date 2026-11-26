.PHONY: dev test lint

dev:
	uvicorn src.app:app --reload

test:
	pytest -q

lint:
	ruff check src tests
