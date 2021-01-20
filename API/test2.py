# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/9/15 11:53
import pandas as pd
import re
# from MappedManage.models import Mapped


def report_main(filename):
    host_info = pd.read_excel(filename, sheet_name=0).to_dict()


    asset_name = asset_key = asset_description = host_info.get('Unnamed: 1').get(
        1)  # 获取ip地址,Unnamed: 1所在列的第二个键（不包含首行）
    asset_score = str(host_info.get('Unnamed: 2').get(1))
    print(asset_name, asset_score)

if __name__=='__main__':
    # filepath = [r'C:\Users\lintechao\Downloads\test\172.20.3.146.xls']
    # for each in filepath:
    #     report_main(each)
    ip = '172.18.20.200 '
    # mip = Mapped.objects.filter(LANip__asset_key__icontains=ip)
    # if mip.exists():
    #     print('ip 存在')
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                "223.168.1.1"):
        print(11)
    level = 2
    level_info = {"信息": "0", "低危": "1", "中危": "2", "高危": "3", "紧急": "4"}
    level = level_info.get(level) if level_info.get(level) else "0"
    print(level)