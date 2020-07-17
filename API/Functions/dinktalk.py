# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/7/10 16:15

import requests
import json
from SeMF.settings import APP_KEY, APP_SECRET, AGENT_ID
from SeMF.redis import Cache
from API import tasks
from RBAC.service import user_process


class DinkTalk:

    @staticmethod
    def get_assess_token(app_key=APP_KEY, app_secret=APP_SECRET):
        """获取assess_token，进行缓存（钉钉默认7200秒失效，缓存时间小于该值）"""
        assess_token = Cache.read_from_cache('access_token')
        if not assess_token:
            url = 'https://oapi.dingtalk.com/gettoken?appkey={}&appsecret={}'.format(app_key, app_secret)
            res = requests.get(url)
            assess_token = json.loads(res.content).get('access_token')
            Cache.write_onetime_cache(value=assess_token, key='access_token')
        return assess_token

    @staticmethod
    def get_user_id_list(assess_token, dep_id):
        """根据部门ID获取该部门内所有员工id"""
        url = 'https://oapi.dingtalk.com/user/getDeptMember?access_token={}&deptId={}'.format(assess_token, dep_id)
        res = requests.get(url)
        res = json.loads(res.content)
        user_id_list = res.get('userIds')
        return user_id_list

    @classmethod
    def save_user_list(cls, assess_token):
        """获取所有部门id，并根据部门id，获取所有部门下员工id，去重后保存所有员工信息到缓存中，键为用户名拼音"""
        # department_list = Cache.read_from_cache('department')
        # if not department_list:
        url = 'https://oapi.dingtalk.com/department/list?access_token={}'.format(assess_token)
        res = requests.get(url)
        res = json.loads(res.content)
        department_list = []
        user_list = []
        user_name_list = []

        for each in res.get('department'):
            department_list.append(each.get('id'))
            # # 对所有部门id进行缓存，减少查询时间
            # Cache.write_onetime_cache(value=department_list, key='department', key_time_id=2)   # 默认缓存一周
            user_list.extend(cls.get_user_id_list(assess_token, each.get('id')))
            user_list = list(set(user_list))

        for each_id in user_list:
            user_info = cls.get_user_info(assess_token, each_id)
            if user_info:
                Cache.write_onetime_cache(value=user_info, key=user_info.get('name'), key_time_id=2)
                user_name_list.append(user_info.get('name'))
        return user_name_list

    @classmethod
    def get_user_info(cls, assess_token, userid):
        """从钉钉接口获取用户详细信息，并返回用户名拼音、id、头像等信息"""
        url = 'https://oapi.dingtalk.com/user/get?access_token={}&userid={}'.format(assess_token, userid)
        res = requests.get(url)
        res = json.loads(res.content)
        user_info = {}
        if res.get('errmsg') == 'ok':
            user_info['name'] = user_process.han_to_pinyin(res.get('name'))  # 姓名拼音，用作缓存key
            user_info['userid'] = res.get('userid')
            user_info['avatar'] = res.get('avatar')  # 钉钉头像

        return user_info

    @classmethod
    def corp_conversation(cls, user, vuln, assess_token, msg, user_name_list, agent_id=AGENT_ID, dept_id_list=None,
                          to_all_user=False):
        """工作通知推送，参数说明见文档https://ding-doc.dingtalk.com/doc#/serverapi2/pgoxpy/e2262dad"""
        url = 'https://oapi.dingtalk.com/topapi/message/corpconversation/asyncsend_v2?access_token={}'.format(
            assess_token)
        data = {}
        userid_list = []
        for name in user_name_list:
            user_info = Cache.read_from_cache(key=user_process.han_to_pinyin(name))
            # 第一次缓存查询不到，查询钉钉接口，更新缓存
            if not user_info:
                # cls.save_user_list(assess_token=assess_token)
                # 用户不存在, 钉钉接口不会判断不存在的用户，强制中断派发请求
                return {'errcode': -1, 'result': '用户{}不存在'.format(name)}
            userid_list.append(user_info.get('userid'))

        data['agent_id'] = agent_id
        if userid_list:
            data['userid_list'] = userid_list
        else:
            return {'errcode': -1, 'result': '无合法用户'}
        data['msg'] = json.dumps(msg)  # 消息体需为json格式
        if dept_id_list:
            data['dept_id_list'] = dept_id_list
        if to_all_user:
            data['to_all_user'] = to_all_user

        # res = requests.post(url=url, data=data)
        # res = json.loads(res.content)
        # # res = {'errcode': 0, 'task_id': 232719853185, 'request_id': '3x1qbs76ef3k'}
        # return res
        # 异步推送
        # tasks.send_conversation(url, data, user, user_name_list, vuln)
        tasks.send_conversation.delay(url, data, user, user_name_list, vuln)
        return {'errcode': 0, 'result': '漏洞已派发'}


if __name__ == '__main__':
    from API.Functions.dingtalk_msg import DingTalkMsg
    # token = DinkTalk.get_assess_token()
    # # info = DinkTalk.get_user_info(token, userid='191152606026429443')
    # msg = {"msgtype": "text", "text": {"content": "推送测试2020/07/15——by tachiulam"}}
    # # msg = DingTalkMsg.vuln_assign_msg
    # info = DinkTalk.corp_conversation(assess_token=token,
    #                                   user_name_list=['lintechao'],
    #                                   msg=msg)
    # print(info)
    # user_l = DinkTalk.get_user_list(token)
    # idd = DinkTalk.get_user_id_list(token, '244605159')

    # print(DinkTalk.han_to_pinyin(info.get('name')))
