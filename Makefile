all: sa2.bin
.PHONY: all
.SECONDARY:

IQUECRYPT ?= iquecrypt
KEY ?= 00000000000000000000000000000000
IV ?= 00000000000000000000000000000000
APP ?= 00000000.app

BUILD_DIR = build
SOURCE_DIR = src
include $(N64_INST)/include/n64.mk
include $(T3D_INST)/t3d.mk

OBJS = $(BUILD_DIR)/main.o

N64_CFLAGS += -std=gnu2x -Os

sa2.z64: N64_ROM_TITLE = "SA2 libdragon test"

app: all
	$(IQUECRYPT) encrypt -app sa2.bin -key $(KEY) -iv $(IV) -o $(APP)

$(BUILD_DIR)/sa2.elf: $(OBJS)

clean:
	rm -rf $(BUILD_DIR) *.z64 *.bin
.PHONY: clean

%.bin: %.z64
	dd if=$< of=$@ bs=16K conv=sync status=none

-include $(wildcard $(BUILD_DIR)/*.d)