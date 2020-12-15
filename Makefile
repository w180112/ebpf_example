############################################################
# ebpf example makefile
############################################################

######################################
# Set variable
######################################	

OS=$(shell lsb_release -si)
ARCH=$(shell uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(shell lsb_release -sr)

CC	= clang
ifeq ($(OS),Ubuntu)
    INCLUDE = -I/usr/include/asm-generic -I/usr/include/x86_64-linux-gnu
else
	INCLUDE = #-I/usr/include/asm-generic -I/usr/include/x86_64-linux-gnu
endif
CFLAGS = $(INCLUDE) -Wall -O2

USR_TARGET = get_pkts
USR_SRC = get_pkts_user.c

KRN_TARGET = get_pkts_kern.o
KRN_SRC = get_pkts_kern.c

USR_OBJ = $(USR_SRC:.c=.o)

SUBDIR = libbpf/src

BUILDSUBDIR = $(SUBDIR:%=build-%)
CLEANSUBDIR = $(SUBDIR:%=clean-%)

all: $(BUILDSUBDIR) $(KRN_TARGET) $(USR_TARGET)

$(BUILDSUBDIR):
	${MAKE} -C $(@:build-%=%)

.PHONY: $(BUILDSUBDIR)

######################################
# Compile & Link
# 	Must use \tab key after new line
######################################
$(KRN_TARGET): 
	$(CC) $(CFLAGS) -target bpf -c $(KRN_SRC) -o $(KRN_TARGET)

$(USR_TARGET): $(USR_OBJ)
	$(CC) $(CFLAGS) -Llibbpf/src $(USR_OBJ) -o $(USR_TARGET) \
	-lelf -lz libbpf/src/libbpf.a

######################################
# Clean 
######################################
clean: $(CLEANSUBDIR)

$(CLEANSUBDIR):
	$(MAKE) -C  $(@:clean-%=%) clean
	rm -f $(USR_TARGET) *.o