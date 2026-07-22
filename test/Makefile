# Test PC (hors device) du classifieur pur de trames Hitag2.
#   make / make run / make build / make clean
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
SRC     = test_hitag_frames.c ../hitag_frames.c ../hitag2_cipher.c
BIN     = test_hitag_frames

.PHONY: all build run clean
all: run
build: $(BIN)
$(BIN): $(SRC) ../hitag_frames.h ../hitag2_cipher.h
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)
run: $(BIN)
	./$(BIN)
clean:
	rm -f $(BIN)
