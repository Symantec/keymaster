# Set GOPATH to a sensible default if not already set.
GOPATH ?= $(HOME)/go

# This is how we want to name the binary output
BINARY=keymaster

# These are the values we want to pass for Version and BuildTime
VERSION=0.4.0
#BUILD_TIME=`date +%FT%T%z`

# Setup the -ldflags option for go build here, interpolate the variable values
#LDFLAGS=-ldflags "-X github.com/ariejan/roll/core.Version=${VERSION} -X github.com/ariejan/roll/core.BuildTime=${BUILD_TIME}"

all:	init-config-host
	cd $(GOPATH)/src; go install -ldflags "-X main.Version=${VERSION}" github.com/Symantec/keymaster/cmd/*

get-deps:
	go get -t ./...

clean:
	rm -f bin/*
	rm -f keymaster-*.tar.gz

init-config-host:
	@test -f cmd/keymaster/config_host.go || cp -p templates/config_host_go cmd/keymaster/config_host.go

${BINARY}-${VERSION}.tar.gz:
	mkdir ${BINARY}-${VERSION}
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" lib/ ${BINARY}-${VERSION}/lib/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" cmd/ ${BINARY}-${VERSION}/cmd/
	rsync -av  misc/ ${BINARY}-${VERSION}/misc/
	cp LICENSE Makefile keymaster.spec README.md ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/

rpm:	${BINARY}-${VERSION}.tar.gz
	rpmbuild -ta ${BINARY}-${VERSION}.tar.gz

tar:	${BINARY}-${VERSION}.tar.gz

test:
	go test -v ./...
