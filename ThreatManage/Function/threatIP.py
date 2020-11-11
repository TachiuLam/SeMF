# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/11/11 17:35

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
    url = 'https://myip.ms/files/blacklist/general/latest_blacklist.txt'
    res = Threatip.sync_threat_ip(url)
