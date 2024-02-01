import os
import json
import logging
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime, date

log = logging.getLogger(__name__)
TRUST_ROLE_NAME = os.getenv('TRUST_ROLE_NAME', 'org-osm-api')
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'us-east-1')
IAM_ROLES_TABLE = os.getenv('IAM_ROLES_TABLE', 'osm_iam_account_roles')
IAM_SUMMARY_TABLE = os.getenv('IAM_SUMMARY_TABLE', 'osm_iam_role_summary')
IAM_DELETED_ROLES = os.getenv('IAM_SUMMARY_TABLE', 'osm_iam_unused_roles')


def serialize(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    raise TypeError ("Type %s not serializable" % type(obj))


def get_iam_client(params):
    account = params.get('account')
    print(account)


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

    iam_client = boto3.client(
        'iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=DEFAULT_REGION
    )

    return iam_client


def list_roles(params):
    iam_client = get_iam_client(params)
    account = params.get('account')
    mode = params.get('mode')

    if mode is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing mode parameter'
            })
        }

    dynamo_table = boto3.resource('dynamodb').Table(IAM_ROLES_TABLE)

    if mode == 'latest':
        try:
            result = dynamo_table.get_item(Key={'account': account}).get("Item")
            if result:
                roles = json.loads(result.get('roles'))
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'account': account,
                        'updatedAt': result.get('updatedAt'),
                        'roles': roles
                    })
                }
        except Exception as err:
            log.error(err)

    result = iam_client.list_roles(MaxItems=100)
    roles = result.get('Roles', [])
    marker = result.get('Marker')

    while marker is not None:
        result = iam_client.list_roles(Marker=marker, MaxItems=100)
        roles = roles + result.get('Roles', [])
        marker = result.get('Marker')

    updated_at = datetime.utcnow().astimezone().isoformat()

    try:
        result = dynamo_table.put_item(
            Item={
                'account': account,
                'updatedAt': updated_at,
                'roles': json.dumps(roles, default=serialize)
            }
        )
    except Exception as err:
        log.error(err)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'account': account,
            'updatedAt': updated_at,
            'roles': roles
        }, default=serialize)
    }


def get_role(params):
    iam_client = get_iam_client(params)
    role_name = params.get('roleName')

    if role_name is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing roleName parameter'
            })
        }

    try:
        result = iam_client.get_role(RoleName=role_name)
        role = result.get('Role')
    except iam_client.exceptions.NoSuchEntityException:
        return {
            'statusCode': 404,
            'body': json.dumps({
                'message': 'role not found'
            })
        }
    except Exception as err:
        msg = f'Get role fail: {err}'
        log.error(msg)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': msg
            })
        }

    return {
        'statusCode': 200,
        'body': json.dumps({
            'role': role
        })
    }


def crate_role(iam_client, deleted_role):
    try:
        role = iam_client.create_role(
            Path=deleted_role['path'],
            RoleName=deleted_role['role_name'],
            AssumeRolePolicyDocument=deleted_role['assume_role_policy_document'],
            MaxSessionDuration=int(deleted_role['max_session_duration']),
            Description= '' if not deleted_role['description'] else deleted_role['description'],
        )['Role']
    except ClientError as err:
        log.error(f"crate_role error: {err}")
        return False

    if deleted_role['tags']:
        try:
            iam_client.tag_role(
                RoleName=role['RoleName'],
                Tags=deleted_role['tags']
            )
        except ClientError as err:
            log.error(f"crate_role tags error: {err}")
            return False

    return role


def create_policy(iam_client, role_name, policy, policy_type):
    if not policy:
        return True

    if policy_type == 'inline':
        try:
            iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=policy['PolicyName'],
                PolicyDocument=policy['PolicyDocument']
            )
            return True
        except ClientError as err:
            log.error(f"crate_policy inline error: {err}")
            return False

    if policy_type == 'managed':
        try:
            policy_res = iam_client.create_policy(
                Path=policy['PolicyPath'],
                PolicyName=policy['PolicyName'],
                PolicyDocument=policy['PolicyDocument']
            )
            return policy_res["Policy"]["Arn"]
        except ClientError as err:
            log.error(f"crate_policy managed error: {err}")
            return False


def attach_role_policy(iam_client, role_name, policy_arn):
    try:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
        return True
    except ClientError as err:
        log.error(f"attach_role_policy error: {err}")
        return False


def delete_role(iam_client, role_name):

    try:
        managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        if managed_policies:
            for policy in managed_policies:
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
                if policy['PolicyArn'].startswith('arn:aws:iam::aws:policy'):
                    continue
                iam_client.delete_policy(PolicyArn=policy['PolicyArn'])
    except Exception as err:
        log.error(err)
        return False

    try:
        inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
        if inline_policies:
            for policy in inline_policies:
                iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy)
    except Exception as err:
        log.error(err)
        return False

    return True


def restore_role(body):
    if body is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing body'
            })
        }

    body = json.loads(body)
    role_id = body.get('roleId')

    if role_id is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing roleId parameter'
            })
        }

    dynamo_table = boto3.resource('dynamodb').Table(IAM_DELETED_ROLES)

    try:
        deleted_role = dynamo_table.get_item(Key={'role_id': role_id}).get("Item")
    except Exception as err:
        log.error(err)

    iam_client = get_iam_client(body)

    role = crate_role(iam_client, deleted_role)

    if not role:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'could not create role'
            })
        }

    create_status = []

    if deleted_role['inline_policies']:
        policy_type = 'inline'
        for inline_policy in deleted_role['inline_policies']:
            create_policy_resp = create_policy(iam_client, role['RoleName'], inline_policy, policy_type)

            create_status.append(create_policy_resp)

    if deleted_role['managed_policies']:
        for managed_policy in deleted_role['managed_policies']:
            if managed_policy.get('PolicyDocument'):
                policy_type = 'managed'
                policy_arn = create_policy(iam_client, role['RoleName'], managed_policy, policy_type)

                create_status.append(policy_arn)

                result = attach_role_policy(iam_client, role['RoleName'], policy_arn)

            else:
                result = attach_role_policy(iam_client, role['RoleName'], managed_policy['PolicyArn'])

            create_status.append(result)

    if False in create_status:
        message = 'create role error'
        deleted = delete_role(iam_client, role['RoleName'])

        if not deleted:
            message = 'delete role error'

        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': message
            })
        }

    try:
        dynamo_table.update_item(
            Key={'role_id': role_id},
            UpdateExpression="set restored=:r, restoredBy=:rb, restoredAt=:ra",
            ExpressionAttributeValues={
                ":r":  True,
                ":rb": body.get('userName'),
                ":ra": datetime.utcnow().astimezone().isoformat()
            }
        )
    except Exception as err:
        log.error(err)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'role created'
        })
    }


def paginate_scan():
    dynamo_table = boto3.resource('dynamodb').Table(IAM_DELETED_ROLES)
    deleted_roles = []

    try:
        result = dynamo_table.scan()
    except Exception as err:
        print(err)
        return False

    deleted_roles.extend(result.get("Items"))

    while result.get('LastEvaluatedKey'):

        try:
            result = dynamo_table.scan(
                ExclusiveStartKey = result['LastEvaluatedKey']
            )
        except Exception as err:
            print(err)
            return False

        deleted_roles.extend(result.get("Items"))

    return deleted_roles


def list_deleted_roles(params):
    # account = params.get('account')
    # dynamo_table = boto3.resource('dynamodb').Table(IAM_DELETED_ROLES)

    # try:
    #     result = dynamo_table.scan()
    #     if result:
    #         return {
    #             'statusCode': 200,
    #             'body': json.dumps(result.get("Items"), default=str)
    #         }
    # except Exception as err:
    #     log.error(err)

    deleted_roles = paginate_scan()

    if deleted_roles:
        return {
            'statusCode': 200,
            'body': json.dumps(deleted_roles)
        }

    return {
        'statusCode': 404,
        'body': ''
    }


def get_deleted_role(params):
    role_id = params.get('roleId')

    if role_id is None:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'message': 'missing roleId parameter'
            })
        }

    dynamo_table = boto3.resource('dynamodb').Table(IAM_DELETED_ROLES)

    try:
        result = dynamo_table.get_item(Key={'role_id': role_id}).get("Item")
        if result:
            return {
                'statusCode': 200,
                'body': json.dumps(result, default=str)
            }
    except Exception as err:
        log.error(err)

        return {
            'statusCode': 404,
            'body': ''
        }


def lambda_handler(event, context):
    http_method = event['requestContext']['http']['method']
    params = event.get('queryStringParameters')
    body = event.get('body')

    fn = params.get('fn')

    if fn == 'list-roles':
        return list_roles(params)
    if fn == 'get-role':
        return get_role(params)
    if fn == 'list-deleted-roles':
        return list_deleted_roles(params)
    if fn == 'get-deleted-role':
        return get_deleted_role(params)

    if http_method == 'POST':
        if fn == 'restore-role':
            return restore_role(body)

    return {
        'statusCode': 404,
        'body': json.dumps({
            'message': 'iamtools fn not found'
        })
    }
