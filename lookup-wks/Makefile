.phony: all clean

FLAGS=-Wall -Wextra -O3 -march=native

DEPS=hash.o compile-trie.o

ALL= benchmark

all: $(ALL)

clean:
	$(RM) $(ALL) $(DEPS)

benchmark: benchmark.c $(DEPS)
	$(CC) $(FLAGS) benchmark.c $(DEPS) -o $@

hash.o: hash.c
	$(CC) $(FLAGS) hash.c -c -o $@

compile-trie.o: compile-trie.c
	$(CC) $(FLAGS) compile-trie.c -c -o $@
