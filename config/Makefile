.PHONY: build

build:
	GOARCH=amd64 GOOS=linux go build -o main main.go
	zip -q main.zip main

deploy: build
	aws lambda update-function-code --function-name osm-config-lambda --zip-file fileb://main.zip
	@rm main main.zip
