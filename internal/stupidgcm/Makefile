.PHONY: gcc
gcc:
	gcc -Wall -Wextra -Wformat-security -Wconversion -lcrypto -c *.c

.PHONY: format
format:
	clang-format --style=WebKit -i *.c *.h
