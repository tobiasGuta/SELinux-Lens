PYTHON ?= python3

.PHONY: run demo test compile
run:
	PYTHONPATH=src $(PYTHON) -m selinux_lens
demo:
	PYTHONPATH=src $(PYTHON) -m selinux_lens --demo
test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v
compile:
	$(PYTHON) -m compileall -q src tests
