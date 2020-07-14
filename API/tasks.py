# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/7/14 10:57

from __future__ import absolute_import
from celery import shared_task
from .Functions.dinktalk import DinkTalk
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task
def refresh_cache():
    token = DinkTalk.get_assess_token()
    res = DinkTalk.save_user_list(assess_token=token)
    print(res)

