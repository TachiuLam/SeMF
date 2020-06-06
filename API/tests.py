from django.test import TestCase
import requests


# Create your tests here.

def rsas_api_test(url, file=None):
    """测试rsas报告导入api"""

    data1 = {
        'hello': 'hello'
    }
    headers = {}
    if file:
        files = {
            'file': (file, open(file, 'rb').read()),
        }
        # r = requests.post(url=url, files=files, data=data1, headers=headers)
        r = requests.post(url=url, data=data1, files=files, headers=headers)
        return r
    return 'error'


if __name__ == '__main__':
    filepath = '/Users/tc.lam/Tachiu/Project/HexoBlog/blog/source/_posts/hello-world.md'
    url1 = 'http://127.0.0.1:8000/api/rsas/'
    r1 = rsas_api_test(url1, filepath)
    print(r1.text)
