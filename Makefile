.phony: build
build:
	./build.bash

.phony: test
test:
	./test.bash

.phony: format
format:
	go fmt ./...
