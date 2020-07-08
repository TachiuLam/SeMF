from django.test import TestCase
import requests
from API.Functions.rsas import RSAS
from SeMF.redis import Cache
from AssetManage.models import AssetUser
from VulnManage.models import Vulnerability_scan
from API.Functions.api_auth import JWT
from django.contrib.auth.models import User
from ldap3 import Server, Connection, ALL, SUBTREE, ServerPool,ALL_ATTRIBUTES
from ldap3 import Server, Connection, ALL, SUBTREE, ServerPool
import random


# Create your tests here.

def rsas_api_test(url, file=None):
    """测试rsas报告导入api"""

    data = {
        'type': 'rsas'
    }
    headers = {
        "Authorization": "Token eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InJvb3QiLCJzaXRlIjoiaHR0cDovL2xvY2FsaG9zdDo4MDAwIn0.11V46DHb5LHsdqVbKuO6d79qZZQGwOeDMakSFfK_aj8"
    }
    if file:
        files = {
            'file': (file, open(file, 'rb').read()),
        }
        r = requests.post(url=url, data=data, files=files, headers=headers)
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
        # r = RSAS.report_main(f)
        # print(r)
    # f2 = r'C:\Users\lintechao\Downloads\740_server_2020_06_30_xls.zip'
    # res = rsas_api_test(url='http://127.0.0.1:8000/api/upload/', file=f2)
    # print(res.text)

    # token鉴权测试
    # u = 'root'
    # r = JWT.generate_jwt(u)
    # print(r)
    # print(type(r))
    # # r= r+b'kjahkhdkashd'
    # d = JWT.decode_jwt(r)
    # print(d)

    # k = ['111','222']
    # key = Cache.write_onetime_cache(k)
    # print(key)
    # r = Cache.read_from_cache(key)
    # print(r,type(r))
    # for each in r:
    #     print(each)
    # user_email = 'lintechao@yingzi.com'
    # user = User.objects.filter(email=user_email).first()
    # print(user)
    # ii = '["520200611279"]'
    # ii = eval(ii)
    # print(ii, type(ii))



    LDAP_SERVER_POOL = ["corp.yingzi.com:389"]
    # ADMIN_DN = "test04"
    # ADMIN_PASSWORD = "1qaz@WSXwaf1"
    SEARCH_BASE = "ou=corp,dc=corp,dc=yingzi,dc=com"
    ADMIN_DN = "yz_semf"
    ADMIN_PASSWORD = "9ik44DENWa8"
    # # SEARCH_BASE = "ou=corp,dc=corp,dc=yingzi,dc=com"


    def ldap_auth(username, password):
        ldap_server_pool = ServerPool(LDAP_SERVER_POOL)
        conn = Connection(ldap_server_pool, user=ADMIN_DN, password=ADMIN_PASSWORD,
                          check_names=True, lazy=False, raise_exceptions=False)

        conn.open()
        conn.bind()

        res = conn.search(
            search_base=SEARCH_BASE,
            search_filter='(sAMAccountName={})'.format(username),
            search_scope=SUBTREE,
            attributes=['cn', 'givenName', 'mail', 'sAMAccountName'],
            paged_size=5
        )

        if res:
            entry = conn.response[0]
            dn = entry['dn']
            attr_dict = entry['attributes']

            # check password by dn
            try:
                conn2 = Connection(ldap_server_pool, user=dn, password=password, check_names=True, lazy=False,
                                   raise_exceptions=False)
                conn2.bind()
                if conn2.result["description"] == "success":
                    return {'auth_res': True, 'mail': attr_dict["mail"], 'sName': attr_dict["sAMAccountName"],
                            'gName': attr_dict["givenName"]}
                else:
                    print(111)
                    return {'auth_res': False}
            except Exception as e:
                print(e)
                return {'auth_res': False}
        else:
            print(222)
            return {'auth_res': False}

    username = 'lintechao'
    passwd = 'Iandi1562618'
    # username = 'test04'
    # passwd = '1qaz@WSXwaf1'
    res = ldap_auth(username, passwd)
    print(res)

    test = None or '1'
    print(test)



    # def generate_password(code_len=16):
    #     all_lowercase = 'abcdefghijklmnopqrstuvwxyz'
    #     all_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    #     all_numbers = '0123456789'
    #     all_punctuations = r'!@#$%^&*'
    #     all_password = all_lowercase + all_uppercase + all_numbers + all_punctuations
    #     code = ''
    #     for _ in range(code_len):
    #         index = random.randint(0, len(all_password) - 1)
    #         code += all_password[index]
    #     return code
    # print(generate_password(16))
