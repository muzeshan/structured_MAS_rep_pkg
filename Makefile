.PHONY: verify test analyze paper clean

verify:
	python scripts/verify_artifact.py
	python scripts/analyze_results.py --verify

test:
	pytest -q

analyze:
	python scripts/analyze_results.py

paper:
	cd paper && latexmk -pdf main.tex

clean:
	rm -rf .pytest_cache build dist *.egg-info
