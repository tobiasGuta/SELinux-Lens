PYTHON ?= python3

.PHONY: run demo test test-prototype compile
run:
	PYTHONPATH=src $(PYTHON) -m selinux_lens
demo:
	PYTHONPATH=src $(PYTHON) -m selinux_lens --demo
test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

test-prototype:
	PYTHONPATH=src:. dbus-run-session -- $(PYTHON) -m unittest discover -s tests/prototype -v

compile:
	$(PYTHON) -m compileall -q src prototype tests
