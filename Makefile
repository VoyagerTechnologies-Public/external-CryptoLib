#
# CryptoLib Makefile
#

# The "LOCALTGTS" defines the top-level targets that are implemented in this makefile
# Any other target may also be given, in that case it will simply be passed through.
LOCALTGTS := all clean debug internal kmc shire wolf
OTHERTGTS := $(filter-out $(LOCALTGTS),$(MAKECMDGOALS))

# As this makefile does not build any real files, treat everything as a PHONY target
# This ensures that the rule gets executed even if a file by that name does exist
.PHONY: $(LOCALTGTS) $(OTHERTGTS)

#
# Commands
#
all:
	$(MAKE) internal
	$(MAKE) kmc
	$(MAKE) wolf

export BUILDDIR ?= $(CURDIR)/build
export BUILD_IMAGE ?= ghcr.io/voyagertechnologies-public/shire-base:latest
export RUNTIME_CRYPTOLIB_IMAGE_NAME ?= shire-cryptolib-$(MISSION)
export SPACECRAFT ?= latest
export MISSION ?= default
export SHIRE_DIR ?= $(CURDIR)/..

# Determine number of parallel jobs to avoid maxing out low-power systems (Raspberry Pi etc.).
# Use `nproc - 1` but ensure at least 1 job.
NPROC := $(shell nproc 2>/dev/null || echo 1)
JOBS := $(shell if [ $(NPROC) -le 1 ]; then echo 1; else expr $(NPROC) - 1; fi)

clean:
	rm -rf $(BUILDDIR)
	rm -rf ./docs/wiki/_build

debug:
	./support/scripts/docker_debug.sh

docs:
	./support/scripts/documentation_build.sh

internal: 
	./support/scripts/internal_docker_build.sh

kmc:
	./support/scripts/kmc_docker_build.sh

shire: clean
	mkdir -p $(BUILDDIR)
	docker run --rm -it -v $(SHIRE_DIR):$(SHIRE_DIR) --name "shire_cryptolib_build" -w $(BUILDDIR) --user $(shell id -u):$(shell id -g) $(BUILD_IMAGE) sh -c 'cmake .. -DMC_INTERNAL=1 -DCRYPTO_LIBGCRYPT=1 -DKEY_INTERNAL=1 -DSA_INTERNAL=1 -DSUPPORT=1 && make -j$(JOBS)'
	docker build -t $(RUNTIME_CRYPTOLIB_IMAGE_NAME):$(SPACECRAFT) -f support/Dockerfile.standalone .

wolf:
	./support/scripts/wolf_docker_build.sh

env:
	./support/scripts/update_env.sh
