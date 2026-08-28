.PHONY: build debug spec install clean

# Release build (optimised, smaller binary)
build:
	crystal build src/greeter.cr -o greeter --release

# Debug build (fast compile, keeps debug symbols)
debug:
	crystal build src/greeter.cr -o greeter

spec:
	crystal spec

# Install setuid-root so the binary can call PAM, setuid, setgid
install: build
	install -m 4755 -o root greeter /usr/local/bin/crystal-greeter

clean:
	rm -f greeter
