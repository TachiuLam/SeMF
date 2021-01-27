# -*- coding: utf-8 -*-
# Tachiu Lam
# techaolin@gamil.com
# 2020/6/16 16:35
import requests
import os
import time


def send_report(url, token, filename=None):
    """定时发送报告脚本，部署在FTP服务器"""
    data = {
        'type': 'rsas'
    }
    headers = {
        "Authorization": token
    }
    if filename:
        files = {
            'file': (filename, open(filename, 'rb').read()),
        }
        r = requests.post(url=url, data=data, files=files, headers=headers)
        return r
    return 'error'


if __name__ == '__main__':
    d_url = 'http://semf.company.com/api/upload/'
    # d_url = 'http://127.0.0.1:8000/api/upload/'
    r_token = "Token x.eyJ1c2VybmFtZSI6InJvb3QiLCJzaXRlIjoia" \
              "HR0cDovL2xvY2FsaG9zdDo4MDAwIn0.xxx"
    file_path = '/data/ftp/'
    # file_path = r'C:\Users\lintechao\Downloads\test'

    all_files = os.listdir(file_path)
    for each_file in all_files:
        if each_file.endswith('.zip'):
            file_name = os.path.join(file_path, each_file)
            res = send_report(url=d_url, token=r_token, filename=file_name)
            print(time.ctime() + '\t' + res.text)
            # 删除报告
            os.remove(file_name)
