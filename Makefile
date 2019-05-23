PREFIX		?=/usr/local
INSTALLDIR	= $(DESTDIR)$(PREFIX)/bin

HOSTOS		:= $(shell uname -s)
GPIOSUPPORT=off

CC		?= gcc
CFLAGS		?= -O3 -Wall -Wextra
CFLAGS 		+= -std=gnu99
INSTFLAGS	= -m 0755

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

all: build

build:
ifeq ($(HOSTOS), Linux)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o hcxpioff hcxpioff.c $(LDFLAGS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o hcxdumptool hcxdumptool.c $(LDFLAGS)
else
	$(info OS not supported)
endif

install: build
ifeq ($(HOSTOS), Linux)
	install $(INSTFLAGS) hcxpioff $(INSTALLDIR)/hcxpioff
	install $(INSTFLAGS) hcxdumptool $(INSTALLDIR)/hcxdumptool
else
	$(info OS not supported)
endif


ifeq ($(HOSTOS), Linux)
	rm -f hcxpioff
	rm -f hcxdumptool
else
	$(info OS not supported)
endif
	rm -f *.o *~


clean:
ifeq ($(HOSTOS), Linux)
	rm -f hcxpioff
	rm -f hcxdumptool
else
	$(info OS not supported)
endif
	rm -f *.o *~


uninstall:
ifeq ($(HOSTOS), Linux)
	rm -f $(INSTALLDIR)/hcxpioff
	rm -f $(INSTALLDIR)/hcxdumptool
else
	$(info OS not supported)
endif
