# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechoa@yingzi.com
# 2020/6/18 16:32

import json
import time
import random
from SeMF.settings import NEVER_REDIS_TIMEOUT, REDIS_TIMEOUT, CUBES_REDIS_TIMEOUT
from django.core.cache import cache


class Cache:

    @staticmethod
    def read_from_cache(key):
        value = cache.get(key)
        if not value:
            data = None
        else:
            data = json.loads(value)
        return data

    @staticmethod
    def write_onetime_cache(value, key=None, key_time_id='3'):
        """使用该方法缓存，未传入键名和缓存时间，则默认设置"""
        key_time = {'1': NEVER_REDIS_TIMEOUT, '2': REDIS_TIMEOUT, '3': CUBES_REDIS_TIMEOUT}
        if not key:
            key = '01' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(random.randint(10000, 100000))
        cache.set(key, json.dumps(value), key_time.get(key_time_id))
        return key
