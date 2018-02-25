INSTALLDIR	= /usr/local/bin

HOSTOS := $(shell uname -s)
OPENCLSUPPORT=off
GPIOSUPPORT=off
DOACTIVE=on
DOSTATUS=on

CC	= gcc
CFLAGS = -std=gnu99 -O3 -Wall -Wextra
INSTFLAGS = -m 0755

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

ifeq ($(GPIOSUPPORT), on)
CFLAGS	+= -DDOGPIOSUPPORT
LFLAGS	= -lwiringPi
endif


all: build

build:
ifeq ($(GPIOSUPPORT), on)
	$(CC) $(CFLAGS) -o hcxpioff hcxpioff.c $(LFLAGS)
endif
ifeq ($(HOSTOS), Linux)
	$(CC) $(CFLAGS) -o hcxdumptool hcxdumptool.c -lrt $(LFLAGS)
endif


install: build
ifeq ($(GPIOSUPPORT), on)
	install $(INSTFLAGS) hcxpioff $(INSTALLDIR)/hcxpioff
endif
ifeq ($(HOSTOS), Linux)
	install $(INSTFLAGS) hcxdumptool $(INSTALLDIR)/hcxdumptool
endif

ifeq ($(GPIOSUPPORT), on)
	rm -f hcxpioff
endif
ifeq ($(HOSTOS), Linux)
	rm -f hcxdumptool
endif
	rm -f *.o *~


clean:
ifeq ($(GPIOSUPPORT), on)
	rm -f hcxpioff
endif
ifeq ($(HOSTOS), Linux)
	rm -f hcxdumptool
endif
	rm -f *.o *~


uninstall:
ifeq ($(GPIOSUPPORT), on)
	rm -f $(INSTALLDIR)/hcxpioff
endif
ifeq ($(HOSTOS), Linux)
	rm -f $(INSTALLDIR)/hcxdumptool
endif
