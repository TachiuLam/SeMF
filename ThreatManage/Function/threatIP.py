# -*- coding: utf-8 -*-
# Tachiu Lam
# techaolin@gamil.com
# 2020/11/11 17:35
import django
django.setup()
import requests
from ThreatManage.models import ThreatIP


class Threatip:
    @staticmethod
    def sync_threat_ip(url):
        """处理myip.ms网站提供的黑名单IP"""
        res = requests.get(url)
        res = res.text
        for each in res.split('\n'):
            # print(type(each), len(each))
            if len(each) > 0 and each[0] != '#':
                r = each.split('\t')
                # 获取保存IP，后续在此步骤后加入IP详细信息查询功能
                ThreatIP.objects.get_or_create(
                threat_ip = r[0],
                )
        return {'result': '威胁IP保存成功'}


if __name__ == '__main__':
    # url = 'https://myip.ms/files/blacklist/general/latest_blacklist.txt'
    # res = Threatip.sync_threat_ip(url)
    file = r'C:\Users\lintechao\Downloads\full_blacklist_database.txt'
    with open(file, 'r') as f:
        f = f.read()
        # print(f, type(f))
        for each in f.split('\n'):
            # print(type(each), len(each))
            if len(each) > 0 and each[0] != '#':
                r = each.split('\t')
                print(r[0])
                ThreatIP.objects.get_or_create(
                    threat_ip=r[0],
                )
                print('导入成功')

    r2 = ThreatIP.objects.get_or_create(
        threat_ip='2001:1c06:2004:1400:1135:55b:4261:3743'
    )
    # print(res)
    print(r2)