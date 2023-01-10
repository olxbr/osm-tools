.PHONY: build upload clean deploy test

function := osm-iam-tools-lambda

deploy:
	zip -q lambda.zip lambda_function.py
	aws lambda update-function-code --function-name $(function) --zip-file fileb://lambda.zip
	rm lambda.zip

test:
	python3 -m unittest discover
