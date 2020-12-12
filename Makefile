############################################################
# ebpf example makefile
############################################################

######################################
# Set variable
######################################	
CC	= clang
INCLUDE = 
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
	-lbpf -lelf -lz

######################################
# Clean 
######################################
clean: $(CLEANSUBDIR)

$(CLEANSUBDIR):
	$(MAKE) -C  $(@:clean-%=%) clean
	rm -f get_pkt *.o