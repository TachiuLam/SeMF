# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechoa@yingzi.com
# 2020/6/18 16:32

import json
import time
import random
from SeMF.settings import NEVER_REDIS_TIMEOUT, CUBES_REDIS_TIMEOUT, REDIS_TIMEOUT
from django.core.cache import cache


class Cache:

    @staticmethod
    def read_from_cache(key):
        value = cache.get(key)
        if value is None:
            data = None
        else:
            data = json.loads(value)
        return data

    @staticmethod
    def write_onetime_cache(value):
        """一次性使用的值使用该方法保存，建立随机key即可"""
        key = '01' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(random.randint(10000, 100000))
        cache.set(key, json.dumps(value), REDIS_TIMEOUT)
        return key


