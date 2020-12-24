CC=gcc
CFLAGS = -Wall -I. --std=gnu99
LDFLAGS=-L. -lmingwex -lstdc++

ifeq ($(DEBUG), 1)
CFLAGS+=-g -O0
else
CFLAGS+=-O2
endif

OUT=ps3

OBJ=mod/util.o mod/misc.o mod/aes.o mod/aes_xts.o mod/kgen.o mod/main.o 

all: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(OUT) $(OBJ)

clean:
	rm -f mod/*.o $(OUT) mod/*~ *~ *.exe mod/*.exe
