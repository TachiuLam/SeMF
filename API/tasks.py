# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/7/14 10:57


from __future__ import absolute_import
import requests
import json
from celery import shared_task
from .Functions import dingtalk
from VulnManage.models import Vulnerability_scan
from NoticeManage.views import notice_add
from celery.utils.log import get_task_logger
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from RBAC.service.ldap_auth import generate_password
from RBAC.models import Profile

logger = get_task_logger(__name__)


@shared_task
def refresh_cache():
    """定时任务：更新钉钉通讯录缓存，更新钉钉用户头像缓存；同步创建钉钉用户到本地"""
    token = dingtalk.DinkTalk.get_access_token()
    user_name_list = dingtalk.DinkTalk.save_user_list(access_token=token)
    # 同步钉钉用户，创建本地用户
    sync_ldap_user(user_name_list)
    # msg = {"msgtype": "text", "text": {"content": "定时推送测试322——by tachiulam"}}
    # info = DinkTalk.corp_conversation(assess_token=token,
    #                                   user_name_list=['lintechao'],
    #                                   msg=msg)


@shared_task
def send_conversation(url, data, username, to_user, vuln):
    """异步派发漏洞，派发结果使用notice模块通知"""
    res = requests.post(url=url, data=data)
    res = json.loads(res.content)
    # res = {'errcode': 0, 'task_id': 232719853185, 'request_id': '3x1qbs76ef3k'}
    # 使用notice进行推送，待添加
    user = get_object_or_404(User, username=username)
    if res.get('errcode') == 0:
        data_message = {
            'notice_title': '漏洞派发成功',
            'notice_body': '漏洞id：{}；操作人员：{}；派发对象：{}'.format(vuln, username, to_user),
            # 'notice_url': '/vuln/user/',
            'notice_type': 'inform',
        }

        notice_add(user, data_message)
        # 保存派发人员 vuln：['520200615431'] <class 'list'>
        for each in vuln:
            v = Vulnerability_scan.objects.filter(vuln_id=each).first()
            v.fix_status = '5'      # 已派发
            v.process_user = None       # 受理人置为空
            v.save()
        return {'errcode': 0, 'result': '漏洞派发成功'}
    else:
        data_message = {
            'notice_title': '漏洞派发失败',
            'notice_body': '漏洞id：{}；操作人员：{}；原因：{}'.format(vuln, user.username, res.get('errmsg')),
            # 'notice_url': '/vuln/user/',
            'notice_type': 'inform',
        }
        notice_add(user, data_message)
        return {'errcode': res.get('errcode'), 'result': '漏洞派发失败'}


def sync_ldap_user(user_name_list):
    """根据钉钉内用户名，创建本地用户，划分默认项目组：其他；默认角色：其他"""

    for username in user_name_list:
        # 判断ldap用户是否已在本地创建
        user_get = User.objects.filter(username=username).first()
        # 若未创建，新建用户，增加本机随机密码
        if not user_get:
            User.objects.create(username=username, password=generate_password(16))
            profile = Profile.objects.filter(username=username).first()
            profile.area = '16'
            profile.roles = '9'
            profile.save()
    return True
