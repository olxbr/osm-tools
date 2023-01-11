import os
import json
import logging
import boto3
from boto3.dynamodb.conditions import Key
from datetime import datetime

log = logging.getLogger(__name__)
KEYPAIRS_TABLE = os.getenv('KEYPAIRS_TABLE', 'osm_ec2_keypairs')
KEYPAIRS_SUMMARY_TABLE = os.getenv('KEYPAIRS_TABLE', 'osm_ec2_keypairs_summary')


def lambda_handler(event, context):
    body = json.loads(event.get('body', '{}'))
    fingerprint = body.get('fingerprint')
    account = body.get('account')
    instance = body.get('instance')
    filename = body.get('filename')

    if fingerprint is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing fingerprint parameter'
            })
        }

    keypairs_table = boto3.resource('dynamodb').Table(KEYPAIRS_TABLE)
    summary_table = boto3.resource('dynamodb').Table(KEYPAIRS_SUMMARY_TABLE)
    found_fingerprint = ''

    try:
        for fp in fingerprint.values():
            if fp != '':
                result = keypairs_table.query(
                    IndexName="fingerprint-index",
                    KeyConditionExpression=Key('fingerprint').eq(fp)
                )
                if result['Count'] > 0:
                    found_fingerprint = fp
                    break
    except Exception as err:
        log.error(f'DynamoDB query error: {err}')

    found = found_fingerprint != ''

    try:
        item = {
            'account': account,
            'instance': instance,
            'filename': filename,
            'scan_date': datetime.utcnow().astimezone().isoformat()
        }

        if found:
            item['found_fingerprint'] = found_fingerprint

        _ = summary_table.put_item(Item=item)
    except Exception as err:
        log.error(f'DynamoDB put_item error: {err}')

    return {
        'statusCode': 200 if found else 404,
        'body': json.dumps({'found_keypair': found})
    }
