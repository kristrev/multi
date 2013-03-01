CC = gcc
CFLAGS = `pkg-config --cflags glib-2.0` -g
LIBS = -l pthread -l iw -l yaml `pkg-config --libs glib-2.0 libmnl`
SRC_FILES = *.c

all: multi_client

multi_client: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f multi_client *.o

.PHONY: clean
