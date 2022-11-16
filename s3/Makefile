.PHONY: build upload clean deploy test

build:
	pip install -r requirements.txt -t build --upgrade
	cp lambda_functions.py build
	cd build && zip -qr ../lambda.zip .

upload:
	aws lambda update-function-code --function-name s3tools-lambda --zip-file fileb://lambda.zip

clean:
	rm -r build
	rm lambda.zip

deploy: build upload clean

test:
	python -m unittest discover
