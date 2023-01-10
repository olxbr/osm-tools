import os
import json
import logging
import boto3
from datetime import datetime

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = os.getenv('TRUST_ROLE_NAME', 'org-osm-api')
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'us-east-1')
S3_SUMMARY_TABLE = os.getenv('S3_SUMMARY_TABLE', 'osm_s3_bucket_summary')


def bucket_status(s3_client, bucket_name):
    try:
        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)['PolicyStatus']['IsPublic']
    except:
        policy_status = None

    try:
        public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
    except:
        public_access_block = None

    if policy_status == None and public_access_block == None: # 0
        return 'Objects can be public'

    elif policy_status == None and public_access_block != None: # public_access_block
        if not all(list(public_access_block.values())):
            return 'Objects can be public'
        if all(list(public_access_block.values())) or public_access_block['IgnorePublicAcls']:
            return 'Bucket and objects not public'

    if policy_status != None and public_access_block == None: # policy
        if policy_status:
            return 'Public'
        else:
            return 'Objects can be public'

    elif policy_status != None and public_access_block != None: # 2
        if policy_status and not all(list(public_access_block.values())):
            return 'Public'
        elif policy_status and all(list(public_access_block.values())):
            return 'Only authorized users of this account'

        if not policy_status and not all(list(public_access_block.values())):
            return 'Objects can be public'

        elif not policy_status and all(list(public_access_block.values())) or public_access_block['IgnorePublicAcls']:
            return 'Bucket and objects not public'


def lambda_handler(event, context):
    body = json.loads(event['Records'][0]['body'])
    message = json.loads(body['Message'])

    account = message['account']
    region = message['region']
    event_name = message['detail']['eventName']
    bucket_name = message['detail']['requestParameters']['bucketName']

    sts_client = boto3.client('sts')
    assumed_role_obj = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account}:role/{TRUST_ROLE_NAME}',
        RoleSessionName='org_osm_role_session'
    )

    credentials = assumed_role_obj['Credentials']
    params = {
        'aws_access_key_id': credentials['AccessKeyId'],
        'aws_secret_access_key': credentials['SecretAccessKey'],
        'aws_session_token': credentials['SessionToken'],
        'region_name': region
    }

    s3 = boto3.resource('s3', **params)
    client = s3.meta.client
    bucket = s3.Bucket(bucket_name)

    if not bucket.creation_date:
        log.info(f'Bucket {bucket_name} not found. Account: {account}')
        return None

    public_status = bucket_status(client, bucket_name)

    try:
        policy = client.get_bucket_policy(Bucket=bucket_name).get('Policy', '')
    except Exception as err:
        policy = ''

    try:
        tags = client.get_bucket_tagging(Bucket=bucket_name).get('TagSet', [])
    except Exception as err:
        tags = []

    current_date = datetime.utcnow().astimezone().isoformat()
    update_exp = "set creation_date=:cd, account=:a, policy=:p, public_status=:ps, tags=:t, updated_at=:u"
    attr_values = {
        ":cd": bucket.creation_date.isoformat(),
        ":a": account,
        ":p": policy,
        ":ps": public_status,
        ":t": tags,
        ":u": current_date
    }

    if event_name == 'DeleteBucket':
        update_exp = "set deleted=:d, updated_at=:u"
        attr_values = {
            ":d": True,
            ":u": current_date
        }

    dynamo_table = boto3.resource('dynamodb').Table(S3_SUMMARY_TABLE)

    try:
        _ = dynamo_table.update_item(
            Key={"bucket": bucket_name},
            UpdateExpression=update_exp,
            ExpressionAttributeValues=attr_values,
            ReturnValues="UPDATED_NEW"
        )
    except Exception as err:
        log.error(f'update_item error: {err}')
        print(f'Error: bucket {bucket_name} not updated! Event: {event_name}')
        raise err

    print(f'Bucket {bucket_name} updated. Event: {event_name}')
