# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/7/27 14:06

import urllib.request
from SeMF.settings import STATICFILES_DIRS


def save_img(img_url, file_name, file_path):
    try:
        res = urllib.request.urlopen(img_url)
        avatar = res.read()
        with open(file_path + file_name, 'wb') as f:
            f.write(avatar)
        return True
    except Exception as e:
        print(e)
        return False


