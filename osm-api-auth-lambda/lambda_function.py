import os
import json
import hmac
import base64
import hashlib
import logging
import boto3

log = logging.getLogger(__name__)
SECRET_ID = os.getenv('SECRET_ID')
SECRET_KEY = os.getenv('SECRET_KEY')
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'us-east-1')


def make_digest(message, key):
    key = bytes(key, 'UTF-8')
    message = bytes(message, 'UTF-8')
    digester = hmac.new(key, message, hashlib.sha1)
    digest = digester.digest()

    return str(base64.urlsafe_b64encode(digest), 'UTF-8')


def make_key(message):
    if SECRET_ID is None or SECRET_KEY is None:
        return False, 'Error: missing SECRET_ID or SECRET_KEY env vars'

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=DEFAULT_REGION)

    try:
        response = client.get_secret_value(SecretId=SECRET_ID)
        secrets = json.loads(response.get('SecretString'))
    except Exception as err:
        return False, f'Error: {err}'

    shared_secret = secrets.get(SECRET_KEY)

    if shared_secret is None:
        return False, 'Error: unable to find shared secret'

    return True, make_digest(message, shared_secret)


def lambda_handler(event, context):
    auth = event['headers']['authorization']
    raw_path = event['rawPath']
    domain_name = event['requestContext']['domainName']
    url = f"https://{domain_name}{raw_path}"

    # raw_query_string = event.get('rawQueryString')
    # if raw_query_string:
    #     url = f"{url}?{raw_query_string}"

    created, value = make_key(url)
    if not created:
        log.error(value)
        return {"isAuthorized": False}

    return {"isAuthorized": auth == value}
