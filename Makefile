TESTS = test.spec.js

all: test

configure:
	node-gyp configure

build: configure
	node-gyp build
	npm install .

test: build
	@./node_modules/nodeunit/bin/nodeunit $(TESTS)

clean:
	node-gyp clean

.PHONY: all build configure test clean
