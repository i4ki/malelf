CC      := gcc

#CFLAGS  := -ggdb -W -Wall  -Wextra -L/usr/local/lib -I/usr/local/include/ -I/usr/include/libxml2/ -lcunit -lmalelf
CFLAGS  := -ggdb -W -Wall  -Wextra -I/usr/local/include/ -I/usr/include/libxml2/ -lcunit -lmalelf

BIN     := bin/malelf

SRC := src/main.c src/dissect.c src/util.c
OBJ := $(patsubst %.c,%.o,$(SRC))

%.o: %.c
		$(CC) $(CFLAGS) -o $@ -c $<

all: $(OBJ)
		$(CC) $(CFLAGS) -o $(BIN) $(OBJ)

clean:
		$(RM) $(BIN) $(OBJ) *.o $(LIB)
