import json
import logging
import boto3

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = 'org-osm-api'


def find_bucket(s3, params):
    bucket_name = params.get('bucketName')
    search_by = params.get('searchBy')
    buckets = []

    if search_by == 'fullname':
        bucket = s3.Bucket(bucket_name)
        if bucket:
            buckets = [{
                'name': bucket.name,
                'creation_date': bucket.creation_date.isoformat()
            }]

    if search_by == 'prefix':
        try:
            for bucket in s3.buckets.all():
                if bucket.name.startswith(bucket_name):
                    buckets.append({
                        'name': bucket.name,
                        'creation_date': bucket.creation_date.isoformat()
                    })
        except Exception as err:
            log.error(f'list buckets error: {err}')
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'message': 'list buckets error'
                })
            }

    return {
        'statusCode': 200,
        'body': json.dumps({
            'buckets': buckets
        })
    }


def lambda_handler(event, context):
    params = event.get('queryStringParameters')
    if not params:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing queryStringParameters'
            })
        }
    
    account = params.get('account')
    if not account:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing account parameter'
            })
        }

    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account}:role/{TRUST_ROLE_NAME}',
        RoleSessionName='org_osm_role_session'
    )

    credentials = assumed_role_object['Credentials']
    s3 = boto3.resource(
        's3',
        aws_access_key_id = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token = credentials['SessionToken']
    )

    fn = params.get('fn')

    if fn == 'find-bucket':
        return find_bucket(s3, params)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'message': 's3tools fn not found'
        })
    }
