import os
import json
import logging
import boto3
from boto3.dynamodb.conditions import Key

log = logging.getLogger(__name__)
KEYPAIRS_TABLE = os.getenv('KEYPAIRS_TABLE', 'osm_ec2_keypairs')


def lambda_handler(event, context):
    params = event.get('queryStringParameters')
    if params is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing parameters'
            })
        }

    fingerprint = params.get('fingerprint')
    if fingerprint is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing fingerprint parameter'
            })
        }

    dynamo_table = boto3.resource('dynamodb').Table(KEYPAIRS_TABLE)

    try:
        result = dynamo_table.query(
            IndexName="fingerprint-index",
            KeyConditionExpression=Key('fingerprint').eq(fingerprint),
        )
        if result['Count'] > 0:
            return {
                'statusCode': 200,
                'body': json.dumps({'exists': True})
            }
    except Exception as err:
        log.error(f'DynamoDB query error: {err}')

    return {
        'statusCode': 404,
        'body': json.dumps({'exists': False})
    }
