#!/usr/bin/python3
# -*- coding : utf-8 -*-
# @Author    : Tachiu Lam
# @Mail      : techaolin@gamil.com
# @Datetime  : 2021/1/14 11:48
# @Software  : PyCharm
import datetime


class DateTime:

    @classmethod
    def time_range(cls, timing=None):
        """处理查询输入的时间范围"""
        if not timing:  # 返回默认查询时间范围
            data_range = ['1899-01-01', str(datetime.datetime.now())]
        else:
            data_range = str(timing).split(' - ')  # 注意前后有空格' - '
        return data_range


if __name__ == '__main__':
    timing1 = '2020-09-01 00:09:00 - 2020-10-31 00:10:00'
    res = DateTime.time_range((timing1))
    print(res)
    print(datetime.datetime.now())