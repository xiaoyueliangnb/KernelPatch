TARGET_COMPILE=/home/xiaokozi/Android/Sdk/ndk/ndk-r27/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/
# ifndef TARGET_COMPILE
#     $(error TARGET_COMPILE not set)
# endif

ifndef KP_DIR
    KP_DIR = ../..
endif


CC = $(TARGET_COMPILE)aarch64-linux-android31-clang
LD = $(TARGET_COMPILE)ld.lld
AS = $(TARGET_COMPILE)llvm-as
OBJCOPY = $(TARGET_COMPILE)llvm-objcopy
STRIP := $(TARGET_COMPILE)llvm-strip

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS = -I$(AP_INCLUDE_PATH) $(INCLUDE_FLAGS) -Wall -Ofast -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden
# CFLAGS = -I$(AP_INCLUDE_PATH) $(INCLUDE_FLAGS) -mllvm -irobf-indbr -mllvm -irobf-icall -mllvm -irobf-indgv -mllvm -irobf-cff -mllvm -irobf-cse -Wall -Ofast -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden
# CFLAGS = -I$(AP_INCLUDE_PATH) $(INCLUDE_FLAGS) -mllvm -irobf-indbr -mllvm -irobf-indgv -mllvm -irobf-cff -mllvm -irobf-cse -Wall -Ofast -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden

LDFLAGS  += -s

objs := tcp-v4.o

all: tcp-v4.kpm

# 链接
tcp-v4.kpm: ${objs}
	${CC}  $(LDFLAGS)  -r -o $@ $^
	${STRIP} -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@

# 编译
%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS)  -Ttcp-v4.lds -c -O2 -o $@ $<


.PHONY: clean
ifeq ($(OS), Windows_NT)
clean:
	del /Q *.o *.kpm
else
clean:
	rm -rf *.o *.kpm
endif