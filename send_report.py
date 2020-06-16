# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechoa@yingzi.com
# 2020/6/16 16:35
import requests
import os


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
    d_url = 'http://172.19.130.20:8000/api/upload/'
    r_token = "Token eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InJvb3QiLCJzaXRlIjoia" \
              "HR0cDovL2xvY2FsaG9zdDo4MDAwIn0.11V46DHb5LHsdqVbKuO6d79qZZQGwOeDMakSFfK_aj8"
    file_path = '/data/ftp/'

    all_files = os.listdir(file_path)
    for each_file in all_files:
        if each_file.endswith('.zip'):
            file_name = os.path.join(file_path, each_file)
            res = send_report(url=d_url, token=r_token, filename=file_name)
            print(res.text)
            # 删除报告
            os.remove(file_name)
