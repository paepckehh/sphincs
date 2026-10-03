PROJECT=$(shell basename $(CURDIR))

info:
	echo $(PROJECT)

all: info

build:
	go build -v 

deps: 
	rm go.mod go.sum
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v	

check: 
	gofmt -w -s .
	staticcheck
