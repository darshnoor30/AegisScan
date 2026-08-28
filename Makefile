.PHONY: install benchmark demo test typecheck lint verify serve clean

install:
	python -m pip install -e ".[tls]"

demo:
	PYTHONPATH=src python -m aegisscan demo --output reports/demo

benchmark:
	PYTHONPATH=src python -m aegisscan benchmark --output reports/benchmark.json

test:
	python -m pytest --cov=aegisscan --cov-report=term-missing

lint:
	python -m ruff check src tests

typecheck:
	python -m mypy src

verify: lint typecheck test demo benchmark
	node --check src/aegisscan/static/app.js
	python -m json.tool schemas/aegisscan-result.schema.json >/dev/null

serve:
	PYTHONPATH=src python -m aegisscan serve

clean:
	python -c "import pathlib,shutil; [shutil.rmtree(p,ignore_errors=True) for p in map(pathlib.Path,['build','dist','.pytest_cache','.ruff_cache','.mypy_cache','htmlcov'])]"
