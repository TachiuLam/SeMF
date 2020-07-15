# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/7/15 10:30


class DingTalkMsg:

    @staticmethod
    def assign_msg(vuln):
        # 漏洞派发钉钉message，类型卡片
        assign_msg = {
            "msgtype": "action_card",
            "action_card": {
                "title": "待处理漏洞推送",
                "markdown": vuln.vuln_name,
                "btn_orientation": "0",
                "btn_json_list": [
                    {
                        "title": "受理",
                        "action_url": "http://127.0.0.1/vuln/user/details/{}".format(vuln.vuln_id)
                    },
                    {
                        "title": "全部受理",
                        "action_url": "https://www.tmall.com"
                    }
                ]
            }
        }
        return assign_msg
