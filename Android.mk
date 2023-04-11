LOCAL_PATH:=$(call my-dir)

ifeq ($(PRODUCTION),1)
VERSION_TAG		:= $(PRODUCTION_VERSION)
else
VERSION_TAG		:= $(shell git describe --tags || echo $(PRODUCTION_VERSION))
endif
VERSION_YEAR	:= $(shell echo $(PRODUCTION_YEAR))

HCX_CFLAGS		:= -std=gnu99 -O3 -Wall -Wextra
HCX_DEFS		:= -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_YEAR=\"$(VERSION_YEAR)\"
HCX_DEFS		+= -DSTATUSOUT -DNMEAOUT

include $(CLEAR_VARS)
LOCAL_MODULE			:= hcxdumptool
LOCAL_CFLAGS			+= $(HCX_CFLAGS) $(HCX_DEFS)
LOCAL_SRC_FILES			:= hcxdumptool.c
include $(BUILD_EXECUTABLE)
