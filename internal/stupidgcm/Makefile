.PHONY: test
test: gcc
	# All three ways of building this must work
	go build
	go build -tags without_openssl
	CGO_ENABLED=0 go build -tags without_openssl
	# Likewise, all three ways of testing this must work
	go test -v
	go test -v -tags without_openssl
	CGO_ENABLED=0 go test -v -tags without_openssl

.PHONY: gcc
gcc:
	gcc -Wall -Wextra -Wformat-security -Wconversion -lcrypto -c *.c

.PHONY: format
format:
	clang-format --style=WebKit -i *.c *.h
