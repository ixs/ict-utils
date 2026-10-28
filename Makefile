.PHONY: check build

check:
	uv run pytest
	uv run ruff check
	uv run ruff format --check
	uv run ty check

build: check
	uv build
