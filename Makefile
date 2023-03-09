all:
	$(CC) -Wall -std=c17 fsimaster_aspeed.c -o fsimaster-aspeed

.PHONY: clean
clean:
	rm -f fsimaster-aspeed
