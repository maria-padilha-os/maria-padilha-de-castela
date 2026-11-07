SHELL := /bin/bash

.PHONY: all test iso check clean

all: test

test:
	bash tests/all.sh

# Build the private ISO. This must run as root inside an Arch container.
iso:
	./build.sh

# Validate the profile without running mkarchiso. Still container-only.
check:
	./build.sh --check

clean:
	rm -rf out .scratch/iso-build
