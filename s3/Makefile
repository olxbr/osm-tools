.PHONY: build deploy test clean

build:
	pip install -r requirements.txt -t build --upgrade
	cp lambda_function.py build
	cd build && zip -qr ../lambda.zip .

deploy: build
	aws lambda update-function-code --function-name s3tools-lambda --zip-file fileb://lambda.zip --no-verify-ssl

test:
	python -m unittest discover

clean:
	rm -r build
	rm lambda.zip
