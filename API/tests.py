from django.test import TestCase
from urllib3 import encode_multipart_formdata
import requests


# Create your tests here.

def rsas_api_test(url, file):
    """测试rsas报告导入api"""
    files = {
        'file': (file, open(file, 'rb').read()),
    }
    data1 = {
        'hello': 'hello'
    }
    encode_data = encode_multipart_formdata(files)
    data = encode_data[0]
    headers = {
        # 'content_type': encode_data[1]
    }
    print(encode_data)
    r = requests.post(url=url, files=files, data=data1, headers=headers)
    return r


if __name__ == '__main__':
    filepath = 'E:\\harbor.txt'
    url1 = 'http://127.0.0.1:8000/api/rsas/'
    r1 = rsas_api_test(url1, filepath)
    print(r1.text)
