all: verify

CFLAGS=-I/usr/include -Wall
LDFLAGS=-lcrypto

verify: verify_sign.o main.o
	$(CC) -o verify verify_sign.o main.o $(CFLAGS) $(LDFLAGS)



clean:
	rm *.o verify
