# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOGET=$(GOCMD) get
BIN=bin
LIB_NAME=eip1962
LIBARY_FULL_NAME=lib$(LIB_NAME).so
LIB_DIR=./lib
SRC=api
CXX=gcc
CXX_FLAGS := -L$(LIB_DIR) -l$(LIB_NAME) -I$(LIB_DIR)

all: clean build test

build: 
		CGO_ENABLED=1 $(GOBUILD) -o $(LIB_DIR)/$(LIBARY_FULL_NAME) -buildmode=c-shared $(SRC)/main.go		
build_static: 
		CGO_ENABLED=1 $(GOBUILD) -o $(LIB_DIR)/$(LIBARY_FULL_NAME) -ldflags "-linkmode external -extldflags -static" $(SRC)/main.go	

clean: 
		$(GOCLEAN)
		rm -f $(LIB_DIR)/*
test:
	# mkdir $(BIN)
	$(CXX) $(CXX_FLAGS) -o $(LIB_DIR)/api_c_test $(SRC)/api.c
	cd lib && ./api_c_test

build-linux:
		CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LIB_DIR)/$(LIBARY_FULL_NAME) -buildmode=c-shared $(SRC)/main.go		
build-macos:
		CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(LIB_DIR)/$(LIBARY_FULL_NAME) -buildmode=c-shared $(SRC)/main.go		