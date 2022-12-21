import unittest
from lambda_function import (lambda_handler, find_bucket, bucket_info,
    list_buckets, get_bucket, bucket_status, get_bucket_summary)


class FakeS3Client:
    pass


class HandlerTest(unittest.TestCase):

    def setUp(self):
        self.fake_event = {
            'queryStringParameters': {},
            'requestContext': {
                'http': {
                    'method': 'GET'
                }
            }
        }

    def test_missing_account_parameter(self):
        result = lambda_handler(self.fake_event, {})
        self.assertEqual(400, result['statusCode'])
        self.assertIn('missing account parameter', result['body'])


class GetBucketTest(unittest.TestCase):

    def setUp(self):
        self.buckets = [{"Name": "bucket1"}, {"Name": "bucket2"}]

    def test_get_bucket_returns_none(self):
        bucket = get_bucket("bucket3", self.buckets)
        self.assertEqual(bucket, None)

    def test_get_bucket_returns_bucket(self):
        bucket = get_bucket("bucket1", self.buckets)
        self.assertEqual(bucket["Name"], "bucket1")


class BucketStatusTest(unittest.TestCase):
    pass


class FindBucketTest(unittest.TestCase):

    def test_missing_bucketName_parameter(self):
        result = find_bucket(FakeS3Client(), {})
        self.assertEqual(400, result['statusCode'])
        self.assertIn('missing bucketName parameter', result['body'])

    def test_missing_searchBy_parameter(self):
        result = find_bucket(FakeS3Client(), {'bucketName': 'test-bucket'})
        self.assertEqual(400, result['statusCode'])
        self.assertIn('missing searchBy parameter', result['body'])


class BucketInfoTest(unittest.TestCase):

    def test_missing_bucketName_parameter(self):
        result = bucket_info(FakeS3Client(), {})
        self.assertEqual(400, result['statusCode'])
        self.assertIn('missing bucketName parameter', result['body'])


class ListBucketsTest(unittest.TestCase):

    def test_missing_mode_parameter(self):
        result = list_buckets(FakeS3Client(), {})
        self.assertEqual(400, result['statusCode'])
        self.assertIn('missing mode parameter', result['body'])


class BucketSymmaryTest(unittest.TestCase):

    def test_get_bucket_summary_missing_bucketName_parameter(self):
        result = get_bucket_summary({})
        self.assertEqual(400, result['statusCode'])
        self.assertIn('missing bucketName parameter', result['body'])


if __name__ == '__main__':
    unittest.main()
