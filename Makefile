.PHONY: build deploy test

build:
	@pip install -r requirements.txt -t build --upgrade
	@cp lambda_function.py build
	@cd build && zip -qr ../lambda.zip .

deploy: build
	@aws lambda update-function-code --function-name s3tools-lambda --zip-file fileb://lambda.zip

test:
	@python -m unittest discover
