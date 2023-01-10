import sys
from lambda_function import make_key

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: python keygen.py <url>')
        sys.exit(1)

    _, value = make_key(sys.argv[1])
    print(value)
