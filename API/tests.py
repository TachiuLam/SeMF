from django.test import TestCase
import requests
from API.Functions.rsas import RSAS
from VulnManage.models import Vulnerability_scan
from API.Functions.api_auth import JWT


# Create your tests here.

def rsas_api_test(url, file=None):
    """测试rsas报告导入api"""

    data1 = {
        'type': 'rsas'
    }
    headers = {
        "Authorization": "Token eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InJvb3QiLCJzaXRlIjoiaHR0cDovL2xvY2FsaG9zdDo4MDAwIn0.11V46DHb5LHsdqVbKuO6d79qZZQGwOeDMakSFfK_aj8"
    }
    if file:
        files = {
            'file': (file, open(file, 'rb').read()),
        }
        r = requests.post(url=url, data=data1, files=files, headers=headers)
        return r
    return 'error'


if __name__ == '__main__':
    # filepath = '/Users/tc.lam/Tachiu/Project/HexoBlog/blog/source/_posts/hello-world.md'
    # url1 = 'http://127.0.0.1:8000/api/upload/'
    # r1 = rsas_api_test(url1, filepath)
    # print(r1.text)

    # windows测试
    file1 = r'C:\Users\lintechao\Downloads\711_2020扫描1.0.2_2020_05_09_xls'
    # Vulnerability_scan.objects.filter(vuln_asset_id=14).delete()
    # Vulnerability_scan.objects.filter(vuln_asset_id=1).delete()

    # fl = RSAS.end_with(file1)
    # for f in fl:
    #     res = rsas_api_test(url='http://127.0.0.1:8000/api/upload/', file=f)
    #     print(res.text)
    #     r = RSAS.report_main(f)
    #     print(r)
    f2 = r'C:\Users\lintechao\Downloads\728_扫描【172.18.129.25】_2020_06_15_xls.zip'
    res = rsas_api_test(url='http://127.0.0.1:8000/api/upload/', file=f2)
    print(res.text)

    # token鉴权测试
    # u = 'root'
    # r = JWT.generate_jwt(u)
    # print(r)
    # print(type(r))
    # # r= r+b'kjahkhdkashd'
    # d = JWT.decode_jwt(r)
    # print(d)
