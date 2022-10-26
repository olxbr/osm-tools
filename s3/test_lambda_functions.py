import unittest
from lambda_functions import lambda_handler, find_bucket, bucket_info, list_buckets


class FakeS3Client:
    pass


class HandlerTest(unittest.TestCase):

    def test_missing_queryStringParameters(self):
        result = lambda_handler({}, {})
        self.assertEqual(400, result['statusCode'])
        self.assertIn('missing queryStringParameters', result['body'])

    def test_missing_account_parameter(self):
        result = lambda_handler({'queryStringParameters': {}}, {})
        self.assertEqual(400, result['statusCode'])
        self.assertIn('missing account parameter', result['body'])


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


if __name__ == '__main__':
    unittest.main()
