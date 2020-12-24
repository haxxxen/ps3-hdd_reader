CC=gcc
CFLAGS = -Wall -I. --std=gnu99
LDFLAGS=-L. -lmingwex -lstdc++

ifeq ($(DEBUG), 1)
CFLAGS+=-g -O0
else
CFLAGS+=-O2
endif

OUT=ps3

OBJ=src/util.o src/misc.o src/aes.o src/aes_xts.o src/kgen.o src/main.o 

all: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(OUT) $(OBJ)

clean:
	rm -f src/*.o $(OUT) src/*~ *~ *.exe src/*.exe
