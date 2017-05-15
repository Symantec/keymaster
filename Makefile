# This is how we want to name the binary output
BINARY=keymaster

# These are the values we want to pass for Version and BuildTime
VERSION=0.1.0
#BUILD_TIME=`date +%FT%T%z`

# Setup the -ldflags option for go build here, interpolate the variable values
#LDFLAGS=-ldflags "-X github.com/ariejan/roll/core.Version=${VERSION} -X github.com/ariejan/roll/core.BuildTime=${BUILD_TIME}"

all:
	go test -v ./...
	mkdir -p bin/
	go build  -o bin/getcreds cmd/getcreds/main.go
	go build  -o bin/keymaster cmd/ssh_usercert_gen/main.go

get-deps:
	go get -t ./...

clean:
	rm -f bin/*
	rm -f keymaster-*.tar.gz

tar:
	mkdir ${BINARY}-${VERSION}
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" lib/ ${BINARY}-${VERSION}/lib/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" cmd/ ${BINARY}-${VERSION}/cmd/
	#mkdir -p ${BINARY}-${VERSION}/ldap_checker/
	#mkdir -p ${BINARY}-${VERSION}/sync_checker/
	#mkdir -p ${BINARY}-${VERSION}/common/
	#cp ldap_checker/*.go ${BINARY}-${VERSION}/ldap_checker/
	#cp sync_checker/*.go ${BINARY}-${VERSION}/sync_checker/
	#cp common/*.go ${BINARY}-${VERSION}/common/
	cp LICENSE Makefile keymaster.spec README.md ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/
