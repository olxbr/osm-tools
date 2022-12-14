import os
import json
import logging
import boto3
from datetime import datetime, date

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = os.getenv('TRUST_ROLE_NAME', 'org-osm-api')
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'us-east-1')


def serialize(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    raise TypeError ("Type %s not serializable" % type(obj))


def find_instance(ec2_client, params):
    ip = params.get('ip')
    ip_type = params.get('ipType', 'public')

    if ip is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing ip parameter'
            })
        }

    filters = {
        'Name': 'ip-address',
        'Values': [ip]
    }

    if ip_type == 'private':
        filters['Name'] = 'private-ip-address'

    instances = []

    try:
        response = ec2_client.describe_instances(Filters=[filters])
        reservations = response['Reservations']
        if len(reservations) > 0:
            instances = reservations[0]['Instances']
    except Exception as err:
        log.error(f'Find by IP error: {err}')

    return {
        'statusCode': 200,
        'body': json.dumps({
            'instances': instances
        }, default=serialize)
    }


def lambda_handler(event, context):
    params = event.get('queryStringParameters')
    account = params.get('account')
    # http_method = event['requestContext']['http']['method']
    # body = event.get('body')

    if account is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing account parameter'
            })
        }

    sts_client = boto3.client('sts')
    assumed_role_obj = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account}:role/{TRUST_ROLE_NAME}',
        RoleSessionName='org_osm_role_session'
    )

    credentials = assumed_role_obj['Credentials']

    ec2_client = boto3.client(
        'ec2',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=DEFAULT_REGION
    )

    fn = params.get('fn')

    if fn == 'find-instance':
        return find_instance(ec2_client, params)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'message': 'ec2tools fn not found'
        })
    }
