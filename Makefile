.PHONY: install test lint typecheck security coverage clean docker-build verify

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

lint:
	ruff check ota_poc/ tests/ scripts/
	ruff format --check ota_poc/ tests/ scripts/

typecheck:
	mypy ota_poc/ scripts/

security:
	bandit -r ota_poc/ -ll

coverage:
	pytest tests/ -v --cov=ota_poc --cov-report=term-missing --cov-fail-under=75

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ .coverage htmlcov/ dist/ build/ *.egg-info/

docker-build:
	docker build -t ota-poc .

docker-run:
	docker run ota-poc --runs 10 --fleet-size 1000

smoke:
	python -m ota_poc.metrics --runs 10 --fleet-size 1000 --ablation

# Full end-to-end verification for reviewers
verify:
	python -m ota_poc.metrics --runs 500 --fleet-size 50000 --seed 42 --ablation
	python scripts/assert_csvs.py
	python scripts/assert_readme_numbers.py

ci: lint typecheck security coverage smoke
