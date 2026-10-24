PROJECT=$(shell basename $(CURDIR))

info:
	echo $(PROJECT)

all: info

build:
	go build -v ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w -s .

check: fmt vet test

lint:
	staticcheck ./...

deps:
	rm go.mod go.sum
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v
