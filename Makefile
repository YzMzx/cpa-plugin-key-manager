PLUGIN_NAME := cpa-plugin-key-manager
BIN_DIR := ./dist

ifeq ($(OS),Windows_NT)
	PLUGIN_EXT := dll
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		PLUGIN_EXT := dylib
	else
		PLUGIN_EXT := so
	endif
endif

OUTPUT := $(BIN_DIR)/$(PLUGIN_NAME).$(PLUGIN_EXT)

.PHONY: all build test clean

all: test build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(OUTPUT) .
	@rm -f $(BIN_DIR)/$(PLUGIN_NAME).h

test:
	go test -v -race ./...

clean:
	rm -rf $(BIN_DIR)
	rm -f $(PLUGIN_NAME).dll $(PLUGIN_NAME).so $(PLUGIN_NAME).dylib $(PLUGIN_NAME).h
