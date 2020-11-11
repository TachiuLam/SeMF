# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/11/11 19:56

from __future__ import absolute_import
from celery import shared_task
from celery.utils.log import get_task_logger
from ThreatManage.Function import threatIP


logger = get_task_logger(__name__)
blackip_url = 'https://myip.ms/files/blacklist/general/latest_blacklist.txt'

@shared_task
def sync_threat_intelligence():
    """定时任务：获取威胁情报，如黑名单IP信息，保存数据库"""
    threatIP.Threatip.sync_threat_ip(url=blackip_url)