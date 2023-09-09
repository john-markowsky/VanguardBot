setup:
	python3 -m venv .env
	@echo "Virtual environment created."

install:
	. .env/bin/activate && \
	pip uninstall -r requirements.txt -y && \
	pip install -r requirements.txt
	@echo "Requirements installed."

test:
	export PYTHONPATH=$(PWD):$$PYTHONPATH; pytest tests/

all: setup install test