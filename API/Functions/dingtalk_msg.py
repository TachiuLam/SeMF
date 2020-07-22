# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/7/15 10:30

from django.shortcuts import get_object_or_404
from VulnManage.models import Vulnerability_scan
from .dinktalk import DinkTalk
from SeMF.settings import AUTH_APP_ID, REDIRECT_URL


class DingTalkMsg:

    @staticmethod
    def assign_msg(vuln_id_list):
        messeage = '### {}个待处理漏洞推送\n'.format(str(len(vuln_id_list)))

        # 漏洞派发钉钉message，类型卡片
        for num, vuln_id in enumerate(vuln_id_list):
            vuln = get_object_or_404(Vulnerability_scan, vuln_id=vuln_id)
            messeage = messeage + str(num+1) + str(vuln.vuln_name) + '\n'

        assign_msg = {
            "msgtype": "action_card",
            "action_card": {
                "title": "{}个待处理漏洞推送".format(str(len(vuln_id_list))),
                "markdown": messeage,
                "btn_orientation": "0",
                "btn_json_list": [
                    # {
                    #     "title": "受理",
                    #     "action_url": "http://127.0.0.1/vuln/user/details/"
                    # },
                    {
                        "title": "漏洞详情",
                        "action_url": DinkTalk.auth_url(AUTH_APP_ID, REDIRECT_URL)
                    },
                ]
            }
        }
        return assign_msg
