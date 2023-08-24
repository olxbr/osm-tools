.PHONY: build upload clean deploy test

function := osm-config-lambda

build:
	GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o bootstrap main.go
	zip -q bootstrap.zip bootstrap

upload:
	aws lambda update-function-code --function-name $(function) --zip-file fileb://bootstrap.zip

clean:
	@rm bootstrap bootstrap.zip

deploy: build upload clean
	@echo "Deployed $(function) to AWS Lambda"

test:
	go test -v ./...
