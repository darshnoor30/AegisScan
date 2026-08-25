.PHONY: install demo test lint serve clean

install:
	python -m pip install -e ".[tls]"

demo:
	PYTHONPATH=src python -m aegisscan demo --output reports/demo

test:
	PYTHONPATH=src python -m unittest discover -s tests -v

lint:
	python -m ruff check src tests

serve:
	PYTHONPATH=src python -m aegisscan serve

clean:
	python -c "import pathlib,shutil; [shutil.rmtree(p,ignore_errors=True) for p in map(pathlib.Path,['build','dist','.pytest_cache','.ruff_cache'])]"

