# This is how we want to name the binary output
BINARY=keymaster

# These are the values we want to pass for Version and BuildTime
VERSION=0.3.2
#BUILD_TIME=`date +%FT%T%z`

# Setup the -ldflags option for go build here, interpolate the variable values
#LDFLAGS=-ldflags "-X github.com/ariejan/roll/core.Version=${VERSION} -X github.com/ariejan/roll/core.BuildTime=${BUILD_TIME}"

all:
	go test -v ./...
	mkdir -p bin/
	cd cmd/prodme; go build  -o ../../bin/prodme  -ldflags "-X main.Version=${VERSION}"
	cd cmd/ssh_usercert_gen; go build  -o ../../bin/keymaster -ldflags "-X main.Version=${VERSION}"
	cd cmd/unlocker; go build  -o ../../bin/keymaster-unlocker -ldflags "-X main.Version=${VERSION}"

get-deps:
	go get -t ./...

clean:
	rm -f bin/*
	rm -f keymaster-*.tar.gz

${BINARY}-${VERSION}.tar.gz:
	mkdir ${BINARY}-${VERSION}
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" lib/ ${BINARY}-${VERSION}/lib/
	rsync -av --exclude="config.yml" --exclude="*.pem" --exclude="*.out" --exclude="*.key" cmd/ ${BINARY}-${VERSION}/cmd/
	rsync -av  misc/ ${BINARY}-${VERSION}/misc/
	cp LICENSE Makefile keymaster.spec README.md ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/

tar:	${BINARY}-${VERSION}.tar.gz

rpm:	${BINARY}-${VERSION}.tar.gz
	rpmbuild -ta ${BINARY}-${VERSION}.tar.gz
