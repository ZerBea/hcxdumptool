PRODUCTION		:= 0
PRODUCTION_VERSION	:= 6.2.7
PRODUCTION_YEAR		:= 2023

ifeq ($(PRODUCTION),1)
VERSION_TAG		:= $(PRODUCTION_VERSION)
else
VERSION_TAG		:= $(shell git describe --tags || echo $(PRODUCTION_VERSION))
endif
VERSION_YEAR		:= $(shell echo $(PRODUCTION_YEAR))

PREFIX		?= /usr
BINDIR		= $(DESTDIR)$(PREFIX)/bin

HOSTOS		:= $(shell uname -s)

CC		?= gcc
CFLAGS		?= -O3 -Wall -Wextra
CFLAGS		+= -std=gnu99
#CFLAGS		+= -ggdb -fsanitize=address
DEFS		= -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_YEAR=\"$(VERSION_YEAR)\"

INSTALL		?= install
INSTFLAGS	=
PKG_CONFIG ?= pkg-config

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

OPENSSL_LIBS=$(shell $(PKG_CONFIG) --libs openssl)
OPENSSL_CFLAGS=$(shell $(PKG_CONFIG) --cflags openssl)

TOOLS=
TOOLS+=hcxdumptool
hcxdumptool_libs=$(OPENSSL_LIBS)
hcxdumptool_cflags=$(OPENSSL_CFLAGS)
TOOLS+=hcxpioff

.PHONY: all build install clean uninstall

all: build

build: $(TOOLS)

.deps:
	mkdir -p .deps

# $1: tool name
define tool-build
$(1)_src ?= $(1).c
$(1)_libs ?=
$(1)_cflags ?=

$(1): $$($(1)_src) | .deps
	$$(CC) $$(CFLAGS) $$($(1)_cflags) $$(CPPFLAGS) -MMD -MF .deps/$$@.d -o $$@ $$($(1)_src) $$($(1)_libs) $$(LDFLAGS) $$(DEFS)

.deps/$(1).d: $(1)

.PHONY: $(1).install
$(1).install: $(1)
	$$(INSTALL) $$(INSTFLAGS) -m 0755 $(1) $$(BINDIR)/$(1)

.PHONY: $(1).clean
$(1).clean:
	rm -f .deps/$(1).d
	rm -f $(1)

.PHONY: $(1).uninstall
$(1).uninstall:
	rm -rf $$(BINDIR)/$(1)

endef

$(foreach tool,$(TOOLS),$(eval $(call tool-build,$(tool))))

install: $(patsubst %,%.install,$(TOOLS))

clean: $(patsubst %,%.clean,$(TOOLS))
	rm -rf .deps
	rm -f *.o *~

uninstall: $(patsubst %,%.uninstall,$(TOOLS))

-include .deps/*.d
