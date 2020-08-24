from django.test import TestCase
import requests
from API.Functions.rsas import RSAS
from SeMF.redis import Cache
from VulnManage.models import Vulnerability_scan
from API.Functions.api_auth import JWT
from django.contrib.auth.models import User
from RBAC.models import Profile
from ldap3 import Server, Connection, ALL, SUBTREE, ServerPool, ALL_ATTRIBUTES
from ldap3 import Server, Connection, ALL, SUBTREE, ServerPool
import random
import json
import time
import jwt
from SeMF.settings import APP_SECRET, ALGORITHM, APP_KEY
import datetime
from RBAC.service.user_process import get_user_area, han_to_pinyin
from API.tasks import refresh_cache

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
    file1 = r'C:\Users\lintechao\Downloads\746_office_2020_07_09_xls.zip'
    # Vulnerability_scan.objects.filter(vuln_asset_id=14).delete()
    # Vulnerability_scan.objects.filter(vuln_asset_id=1).delete()

    # fl = RSAS.end_with(file1)
    # for f in fl:
    #     res = rsas_api_test(url='http://127.0.0.1:8000/api/upload/', file=f)
    #     print(res.text)
    # r = RSAS.report_main(f)
    # print(r)
    f2 = r'C:\Users\lintechao\Downloads\746_office_2020_07_09_xls.zip'
    # res = rsas_api_test(url='http://127.0.0.1:8000/api/upload/', file=f2)
    # print(res.text)
    #
    # # 资产类型判断测试
    # filename = '746_office_2020_07_09_xls.zip'
    # asset_type = RSAS.report_type(filename)
    # print(asset_type)

    # token鉴权测试
    u = 'root'
    tt = time.ctime()
    print(type(tt))
    r = JWT.generate_jwt(u)
    print(r)
    # print(type(r))
    # # r= r+b'kjahkhdkashd'
    r = 'Token eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImxpbnRlY2hhbyIsInNpdGUiOiJodHRwOi8vbG9jYWxob3N0OjgwMDAifQ.UY0IYz7CrwcI-jrVznruQkMOjHmmQ5Y3mlY8U6YHxsE'
    d = JWT.decode_jwt(r)
    print(d)

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
    # res = ldap_auth(username, passwd)
    # print(res)

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

    # 告警平台钉钉推送测试
    url = 'http://ywalert.yingzi.com/api/v1/alert/event/unified'
    headers = {"Content-Type": "application/json;charset=utf-8"}

    body = {
        "secret": "iZTqtwig7bejKRmU",
        "source": "prometheus",
        "trigger": 1,
        "error_type": "default",
        "content": "主机 127.0.0.1 cpu负载超过80%",
        "grade": "重要",
        "title": "主机监控",
        "date": "",
        "hostgroup": "",
        "hostname": "linlinlin",
        "hostip": "127.0.0.1",
        "customized": 1,
        "tools": "normal",
        "user": "*lintechao",
        "reportuser": "*lintechao"
    }
    # res = requests.post(url=url, data=json.dumps(body), headers=headers)
    # print(res.status_code, res.text)

    numl = '林特超； 林小超'
    a = numl.replace(' ', '').split('；')
    print(a)
    print(int(time.time() * 1000))
    name = 'pts'

    # user_id = User.objects.filter(username=name).values('id').first().get('id')
    # profile_id = Profile.objects.filter(user_id=user_id).values('area').all
    # print(user_id, profile_id)
    # r = get_user_area(name).get('user_area_list')
    # print(r)
    vuln_list = Vulnerability_scan.objects.filter(
        # vuln_asset__asset_area__in=r,
        # fix_status__icontains='2',
        leave__gte=1,
    ).exclude(fix_status__icontains='2').exclude(fix_status__icontains='1').order_by('-fix_status', '-leave')
    print(vuln_list)
    for each in vuln_list:
        print(each.fix_status)
    # user_area = Profile.objects.filter(user=user).values('area').all()
    def test(u, **kwargs):
        a = {}

        for v, each in kwargs.items():
            a[v] = each
        a['a'] = u
        return a

    res = test(1)
    print(res)

    # a= '["009","010"]'
    # # a = None
    # a = str(a)
    # a= eval(a)
    # a.extend(['009', "010"])
    # print(a)
    # a = None
    # a= str(a)
    # if not a:
    #     print(22)
    #
    # # refresh_cache()
    name = Cache.get_value(key='lintechao')
    # info = Cache.get_value(key='191152606026429443')
    print(name)
    #
    # user_name = han_to_pinyin('pts')
    # res = get_user_area(user_name)
    # print(res)
    # tk_user_name_zh = 'tk_' + '林特超'
    # user_name_zh = tk_user_name_zh.split('tk_')[1]
    # print(user_name_zh)
    #
    # v_id = 'yz' + '122131231'
    # print(v_id.split('yz')[1])
    print(datetime.date.today())

