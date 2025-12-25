BUILD_DIR?=../build/sim/

include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak

#==============================================================================
# wolfSSL includes
#==============================================================================

SRCS += $(wildcard wolfcrypt/src/*.c)
SRCS += $(wildcard src/*.c)

#==============================================================================
# Object files
#==============================================================================

# Core objects
OBJECTS  = crt0.o main.o

# DTLS client modules
OBJECTS += dtls_client.o
OBJECTS += wolfssl_io.o
OBJECTS += liteeth_udp.o

# wolfSSL crypto
OBJECTS += $(SRCS:.c=.o)

#==============================================================================
# Include paths
#==============================================================================

INC  = -I./wolfssl -I./wolfssl/wolfcrypt -I.

# LiteETH includes (adjust path as needed for your LiteX installation)
INC += -I../litex/litex/soc/software
INC += -I../litex/litex/soc/software/libliteeth

all: boot.bin

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

vpath %.a $(PACKAGES:%=../%)

# CFLAGS += $(INC) -DWOLFSSL_USER_SETTINGS

CFLAGS += $(INC) 
CFLAGS += -DWOLFSSL_USER_SETTINGS

boot.elf: $(OBJECTS)
	$(CC) $(LDFLAGS) -T linker.ld -N -o $@ \
		$(OBJECTS) \
		$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
		-Wl,--whole-archive \
		-Wl,--gc-sections \
		-Wl,-Map,$@.map \
		$(LIBS:lib%=-l%)

ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

# pull in dependency info for *existing* .o files
-include $(OBJECTS:.o=.d)

donut.o: CFLAGS   += -w

VPATH = $(BIOS_DIRECTORY):$(BIOS_DIRECTORY)/cmds:$(CPU_DIRECTORY)


%.o: %.cpp
	$(compilexx)

%.o: %.c
	$(compile)

%.o: %.S
	$(assemble)

clean:
	$(RM) $(OBJECTS) boot.elf boot.bin .*~ *~
	$(RM) dtls_client.o wolfssl_io.o liteeth_udp.o

.PHONY: all clean
