# -*- coding: utf-8 -*-
# Tachiu Lam
# techaolin@gamil.com
# 2020/7/8 14:06

from ldap3 import Connection, SUBTREE, Server, ALL
from SeMF.settings import SEARCH_BASE, LDAP_SERVER_POOL, ADMIN_DN, ADMIN_PASSWORD
import random


def ldap_auth(username, password):
    """
    ldap认证判断，认证成功返回认证状态、用户邮箱、用户名等信息
    :param username:
    :param password:
    :return: {'auth_res': True, 'mail': attr_dict["mail"], 'sAMAccountName': attr_dict["sAMAccountName"],
                        'givenName': attr_dict["givenName"]}
    """
    # ldap_server_pool = ServerPool(LDAP_SERVER_POOL)
    # conn = Connection(ldap_server_pool, user=ADMIN_DN, password=ADMIN_PASSWORD, check_names=True, lazy=False,
    #                   raise_exceptions=False)

    server = Server(LDAP_SERVER_POOL[0], use_ssl=True, get_info=ALL)
    conn = Connection(server, user=ADMIN_DN, password=ADMIN_PASSWORD, check_names=True, lazy=False,
                      raise_exceptions=False )

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
            # conn2 = Connection(ldap_server_pool, user=dn, password=password, check_names=True, lazy=False,
            #                    raise_exceptions=False)
            conn2 = Connection(server, user=dn, password=password, check_names=True, lazy=False,
                              raise_exceptions=False)
            conn2.bind()
            if conn2.result["description"] == "success":
                return {'auth_res': True, 'mail': attr_dict["mail"], 'sAMAccountName': attr_dict["sAMAccountName"],
                        'givenName': attr_dict["givenName"]}
            else:
                return {'auth_res': False}
        except Exception as e:
            print(e)
            return {'auth_res': False}
    else:
        return {'auth_res': False}


def generate_password(code_len=16):
    """生成由大小写字母、数字、部分特殊符号默认16位的密码"""
    all_lowercase = 'abcdefghijklmnopqrstuvwxtc'
    all_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXtc'
    all_numbers = '0123456789'
    all_punctuations = r'!@#$%^&*'
    all_password = all_lowercase + all_uppercase + all_numbers + all_punctuations
    code = ''
    for _ in range(code_len):
        index = random.randint(0, len(all_password) - 1)
        code += all_password[index]
    return code
