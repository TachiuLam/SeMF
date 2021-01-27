# -*- coding: utf-8 -*-
# Tachiu Lam
# techaolin@gmail.com
# 2020/11/18 14:45

import time
from SeMF.settings import EMAIL_HOST, EMAIL_HOST_PASSWORD, EMAIL_HOST_USER


nat_mail_info = {
    # 邮箱服务器
    "mail_server": EMAIL_HOST,
    # 发送邮箱
    "from_addr": EMAIL_HOST_USER,
    # 邮箱授权码
    "password":  EMAIL_HOST_PASSWORD,
    # 接收邮箱
    "toaddrs": [''],

    # 邮件内容
    "content" :'防火墙发现不在白名单内的服务器NAT映射！',
    # 邮件标题
    "now_time": str(time.strftime('%Y-%m-%d', time.localtime(time.time()))),
    "title" : '防火墙端口映射检查  ' + str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))),
    "filepath": r'E:\PycharmProject\semf\static\images\bg.png',
    "filename": 'res'+ str(time.strftime('%Y-%m-%d', time.localtime(time.time()))) + '.png'
}

dingtalk_info = {
    'username_list': ['林xx','','']

}

if __name__ == '__main__':
    print(nat_mail_info)
    print(dingtalk_info)