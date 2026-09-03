.PHONY: test attack verify lint demo demo-gif gate clean
POLICY ?= examples/strict.yaml

test:
	python -m pytest -q

attack:
	python -m railward.cli attack --policy $(POLICY) --key keys/demo.pem --out proof.json

verify:
	python -m railward.cli verify proof.json --pubkey keys/demo.pub

lint:
	python -m railward.cli lint --policy $(POLICY)

demo:
	python examples/demo.py

demo-gif:            # regenerate assets/demo.gif from real CLI output (needs .[demo])
	python assets/make_demo.py

gate:
	bash publish_gate.sh

clean:
	rm -rf proof.json keys */__pycache__ __pycache__ .pytest_cache *.egg-info
