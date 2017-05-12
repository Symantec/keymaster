# This is how we want to name the binary output
BINARY=keymaster

# These are the values we want to pass for Version and BuildTime
VERSION=0.7.5
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

tar:
	mkdir ${BINARY}-${VERSION}
	mkdir -p ${BINARY}-${VERSION}/ldap_checker/
	mkdir -p ${BINARY}-${VERSION}/sync_checker/
	mkdir -p ${BINARY}-${VERSION}/common/
	cp ldap_checker/*.go ${BINARY}-${VERSION}/ldap_checker/
	cp sync_checker/*.go ${BINARY}-${VERSION}/sync_checker/
	cp common/*.go ${BINARY}-${VERSION}/common/
	cp LICENSE Makefile ldap-checker.spec ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/	
