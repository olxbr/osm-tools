import os
import json
import logging
import boto3
from datetime import datetime

log = logging.getLogger(__name__)
KEYPAIRS_TABLE = os.getenv('KEYPAIRS_TABLE', 'osm_ec2_keypairs')


def lambda_handler(event, context):
    body = json.loads(event['Records'][0]['body'])
    message = json.loads(body['Message'])

    account = message['account']
    region = message['region']
    event_name = message['detail']['eventName']
    key_name = message['detail']['requestParameters']['keyName']

    dynamo_table = boto3.resource('dynamodb').Table(KEYPAIRS_TABLE)

    if event_name == 'CreateKeyPair':
        try:
            _ = dynamo_table.put_item(
                Item={
                    'key_name': key_name,
                    'fingerprint': message['detail']['responseElements']['keyFingerprint'],
                    'account': account,
                    'region': region,
                    'created_at': datetime.utcnow().astimezone().isoformat()
                }
            )
        except Exception as err:
            log.error(f'DynamoDB put_item error: {err}')

    if event_name == 'DeleteKeyPair':
        try:
            _ = dynamo_table.delete_item(Key={'key_name': key_name})
        except Exception as err:
            log.error(f'DynamoDB delete_item error: {err}')

    print(f'Event: {event_name}, Keypair: {key_name}.')
