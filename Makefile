

cmd/https-cert/http-cert:
	cd cmd/https-cert && go build -gcflags="-trimpath=${PWD}"

