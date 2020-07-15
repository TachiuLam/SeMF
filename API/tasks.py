# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/7/14 10:57


from __future__ import absolute_import
import requests
import json
from celery import shared_task
from .Functions import dinktalk
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task
def refresh_cache():
    """定时任务：更新钉钉通讯录缓存"""
    token = dinktalk.DinkTalk.get_assess_token()
    dinktalk.DinkTalk.save_user_list(assess_token=token)
    # msg = {"msgtype": "text", "text": {"content": "定时推送测试322——by tachiulam"}}
    # info = DinkTalk.corp_conversation(assess_token=token,
    #                                   user_name_list=['lintechao'],
    #                                   msg=msg)


@shared_task
def send_conversation(url, data):
    """异步派发漏洞，派发结果使用notice模块通知"""
    res = requests.post(url=url, data=data)
    print(res.text)
    res = json.loads(res.content)
    # res = {'errcode': 0, 'task_id': 232719853185, 'request_id': '3x1qbs76ef3k'}
    # 使用notice进行推送，待添加
    if res.get('errcode') == 0:
        return {'errcode': 0, 'result': '派发成功'}
    else:
        return {'errcode': -1, 'result': '派发失败'}
