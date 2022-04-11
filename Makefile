run: main.go
	go run main.go

build: main.go
	go build -o bin/shenc main.go
	GOOS=darwin GOARCH=amd64 go build -o bin/shencmac main.go
	GOOS=linux GOARCH=amd64 go build -o bin/shenclinux main.go

buildall: main.go
	if [ ! -d bin/mac ]; then mkdir -p bin/mac;fi
	if [ ! -d bin/solaris ]; then mkdir -p bin/solaris;fi
	if [ ! -d bin/win ]; then mkdir -p bin/win;fi
	if [ ! -d bin/linux ]; then mkdir -p bin/raspi;fi
	GOOS=darwin GOARCH=amd64 go build -o bin/mac/shenc main.go
	GOOS=solaris GOARCH=amd64 go build -o bin/solaris/shenc main.go
	GOOS=windows GOARCH=amd64 go build -o bin/win/shenc.exe main.go
	GOOS=windows GOARCH=386 go build -o bin/win/shenc86.exe main.go
	GOOS=linux GOARCH=amd64 go build -o bin/linux/shenc main.go
	GOOS=linux GOARCH=arm go build -o bin/linux/shencarm main.go

clean:
	rm -rf bin
