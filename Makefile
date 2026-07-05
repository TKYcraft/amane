VERSION_DATE  := $(shell git show -s --format=%cd --date=format:%Y%m%d HEAD 2>/dev/null || echo 00000000)
VERSION_SHA   := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
VERSION_DIRTY := $(shell git diff-index --quiet HEAD 2>/dev/null || echo -dirty)
VERSION       := $(VERSION_DATE)-$(VERSION_SHA)$(VERSION_DIRTY)

.PHONY: dist test race clean help

help:
	@echo "make dist   - cross-compile release binaries via Docker into dist/build/"
	@echo "make test   - run unit tests"
	@echo "make race   - run unit tests with -race"
	@echo "make clean  - remove built binaries"
	@echo ""
	@echo "VERSION=$(VERSION)"

dist:
	docker buildx build --build-arg VERSION=$(VERSION) -o dist/build/ .
	@echo
	@ls -la dist/build/

test:
	go test ./...

race:
	go test -race ./...

clean:
	rm -rf dist/build/
