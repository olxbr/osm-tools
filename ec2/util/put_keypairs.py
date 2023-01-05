import os
import boto3

DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE', 'osm_ec2_keypairs')
REGIONS = ['us-east-1', 'sa-east-1']

dynamo_session = boto3.session.Session()
dynamodb = dynamo_session.resource('dynamodb', region_name='us-east-1')
dynamodb_table = dynamodb.Table(DYNAMODB_TABLE)


def put_dynamodb_keypairs(boto3_session, region):
    sts_client = boto3_session.client('sts')
    account = sts_client.get_caller_identity().get('Account')

    if not account:
        print("Can't get account id")
        return

    ec2_client = boto3_session.client('ec2', region)
    data = ec2_client.describe_key_pairs()
    keypairs = data.get('KeyPairs', [])

    print(f'Adding {len(keypairs)} keypairs from account {account}, region {region}...', end=' ')

    try:
        with dynamodb_table.batch_writer() as batch:
            for keypair in keypairs:
                _ = batch.put_item(
                    Item={
                        "key_name": keypair['KeyName'],
                        'fingerprint': keypair['KeyFingerprint'],
                        'account': account,
                        'key_region': region,
                        'created_at': keypair['CreateTime'].astimezone().isoformat()
                    }
                )
    except Exception as err:
        print(f'batch put_item error: {err}')
        return

    print('Done')


def run():
    profiles = boto3.session.Session().available_profiles
    f = open('put_keypairs_profiles_done', 'a+')
    f.seek(0)
    done = f.read().splitlines()
    remaining = list(set(profiles) - set(done))
    remaining.sort()

    print(f'{len(profiles)} aws profiles, {len(remaining)} remaining')

    for profile in remaining:
        r = input(f'\nProfile: {profile}, Continue? [Y/n/s] ')

        if r == 's':
            continue

        if r not in ('Y', 'y', ''):
            break

        session = boto3.Session(profile_name=profile)
        for region in REGIONS:
            put_dynamodb_keypairs(session, region)

        f.write(f'{profile}\n')

    f.close()
    print('Finished.')


if __name__ == "__main__":
    run()
