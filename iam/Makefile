.PHONY: build upload clean deploy test

build:
	pip install -r requirements.txt -t build --upgrade
	cp lambda_function.py build
	cd build && zip -qr ../lambda.zip .

upload:
	aws lambda update-function-code --function-name osm-iam-tools-lambda --zip-file fileb://lambda.zip

clean:
	rm -r build
	rm lambda.zip

deploy: build upload clean

test:
	python -m unittest discover
