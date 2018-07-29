CC ?= clang
CFLAGS ?= -Wall -Wextra -pedantic -std=c99

.PHONY: all
all:
	$(CC) $(CFLAGS) vtable.c -o vtable

.PHONY: clean
clean:
	$(RM) vtable
