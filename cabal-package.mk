# -*- makefile-gmake -*-
#
# Variables:
#
#   CONFIGURE_ARGS :: arguments to be passed to ./Setup configure
#     default: --disable-optimization
#
#   RUN_COMMAND :: command to be run for "make run"
#

GHC      ?= ghc
FIND     ?= find
RM_RF    ?= rm -rf
SUDO     ?= sudo
AUTOCONF ?= autoconf
HLINT    ?= hlint
HPC      ?= hpc
DITZ     ?= ditz

CONFIGURE_ARGS ?= --disable-optimization
HADDOCK_OPTS   ?= --hyperlink-source
HLINT_OPTS     ?= \
	--hint=Default --hint=Dollar --hint=Generalise \
	--cross \
	--ignore="Parse error" \
	--report=dist/report.html

SETUP_FILE := $(wildcard Setup.*hs)
CABAL_FILE := $(wildcard *.cabal)
PKG_NAME   := $(CABAL_FILE:.cabal=)

ifeq ($(shell ls configure.ac 2>/dev/null),configure.ac)
  AUTOCONF_AC_FILE := configure.ac
  AUTOCONF_FILE    := configure
else
  ifeq ($(shell ls configure.in 2>/dev/null),configure.in)
    AUTOCONF_AC_FILE := configure.in
    AUTOCONF_FILE    := configure
  else
    AUTOCONF_AC_FILE :=
    AUTOCONF_FILE    :=
  endif
endif

BUILDINFO_IN_FILE := $(wildcard *.buildinfo.in)
BUILDINFO_FILE    := $(BUILDINFO_IN_FILE:.in=)

all: build

build: setup-config build-hook
	./Setup build
	$(RM_RF) *.tix

build-hook:

ifeq ($(RUN_COMMAND),)
run:
	@echo "cabal-package.mk: No command to run."
	@echo "cabal-package.mk: If you want to run something, define RUN_COMMAND variable."
else
run: build
	@echo ".:.:. Let's go .:.:."
	$(RUN_COMMAND)
endif

setup-config: dist/setup-config setup-config-hook $(BUILDINFO_FILE)

setup-config-hook:

dist/setup-config: $(CABAL_FILE) Setup $(AUTOCONF_FILE)
	./Setup configure $(CONFIGURE_ARGS)

$(AUTOCONF_FILE): $(AUTOCONF_AC_FILE)
	$(AUTOCONF)

$(BUILDINFO_FILE): $(BUILDINFO_IN_FILE) configure
	./Setup configure $(CONFIGURE_ARGS)

Setup: $(SETUP_FILE)
	$(GHC) --make Setup

reconfigure:
	rm -f dist/setup-config
	$(MAKE) setup-config

clean: clean-hook
	$(RM_RF) dist Setup *.o *.hi .setup-config *.buildinfo *.tix .hpc
	$(FIND) . -name '*~' -exec rm -f {} \;

clean-hook:

doc:
	rm -rf haddocks
	cabal haddock-project --hackage
# then go to ./haddocks, rename -internal to -docs, tar and upload

install: build
	$(SUDO) ./Setup install

sdist: setup-config
	./Setup sdist

test: build
	$(RM_RF) dist/test
	./Setup test
	if ls *.tix >/dev/null 2>&1; then \
		$(HPC) sum --output="merged.tix" --union --exclude=Main *.tix; \
		$(HPC) markup --destdir="dist/hpc" --fun-entry-count "merged.tix"; \
	fi

# -- Find FIXME Tags ----------------------------------------------------------
fixme:
	@$(FIND) . \
		\( -name 'dist' -or -name '.git' -or -name '_darcs' \) -prune \
		-or \
		\( -name '*.c'   -or -name '*.h'   -or \
		   -name '*.hs'  -or -name '*.lhs' -or \
		   -name '*.hsc' -or -name '*.cabal' \) \
		-exec egrep 'FIXME|THINKME|TODO' {} \+ \
		|| echo 'No FIXME, THINKME, nor TODO found.'

# -- HLint --------------------------------------------------------------------
HLINT_TARGETS ?= $$(find -E . -type d -name dist -prune -o -regex '.*\.(hsc?|lhs)' -print)
lint:
	$(HLINT) $(HLINT_TARGETS) $(HLINT_OPTS)

# -- Ditz the Distributed Issue Tracker ---------------------------------------
ifeq (,$(wildcard .ditz-config))
ditz:
else
ditz:
	$(DITZ) html dist/ditz

ChangeLog:
	rm -f $@
	$(DITZ) releases | awk '{print $$1}' | sort --reverse | while read i; do \
		$(DITZ) changelog $$i >> $@; \
	done
	head $@
endif

# -- Pushing to remote hosts --------------------------------------------------
push: push-repo push-ditz push-doc

push-repo:
	if [ -d "_darcs" ]; then \
		darcs push; \
	elif [ -d ".git" ]; then \
		git push --all && git push --tags; \
	fi

push-ditz: ditz
	if [ -d "dist/ditz" ]; then \
		rsync -av --delete \
			dist/ditz/ \
			www@nem.cielonegro.org:static.cielonegro.org/htdocs/ditz/$(PKG_NAME); \
	fi

push-doc: doc
	if [ -d "dist/doc" ]; then \
		rsync -av --delete \
			dist/doc/html/$(PKG_NAME)/ \
			www@nem.cielonegro.org:static.cielonegro.org/htdocs/doc/$(PKG_NAME); \
	fi

# -- Phony Targets ------------------------------------------------------------
.PHONY: build build-hook setup-config setup-config-hook run clean clean-hook \
		install doc sdist test lint push push-repo push-ditz push-doc \
		ChangeLog
