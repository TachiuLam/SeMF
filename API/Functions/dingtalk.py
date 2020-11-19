# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/7/10 16:15

import requests
import json
import time
import hashlib
import hmac
import base64
from urllib import parse
from SeMF.settings import APP_KEY, APP_SECRET, AGENT_ID
from SeMF.redis import Cache
from API import tasks
from RBAC.service import user_process
from API.Functions.save_img import save_img
from SeMF.settings import STATICFILES_DIRS, STATIC_URL


class DinkTalk:

    @staticmethod
    def auth_url(auth_app_id, redirect_url):
        """构造获取临时授权码的跳转链接"""
        data = {
            "appid": auth_app_id,
            "redirect_uri": redirect_url,
            "response_type": "code",
            "scope": "snsapi_auth",
            "state": "STATE"
        }
        auth_url = F'''https://oapi.dingtalk.com/connect/oauth2/sns_authorize?{parse.urlencode(data)}'''
        return auth_url

    @classmethod
    def get_user_name_by_code(cls, code, access_token, auth_app_id, auth_app_secret):
        """服务端通过临时授权码获取授权用户的个人信息，临时授权码只能使用一次。缓存用户信息"""
        timestamp = str((int(round(time.time() * 1000))))
        # 构造签名
        signature = base64.b64encode(
            hmac.new(auth_app_secret.encode('utf-8'), timestamp.encode('utf-8'), digestmod=hashlib.sha256).digest())
        # urlEncode 签名
        signature = parse.quote(signature.decode("utf-8"))
        data = {'tmp_auth_code': code}
        url = 'https://oapi.dingtalk.com/sns/getuserinfo_bycode?accessKey={}&timestamp={}&signature={}'.format(
            auth_app_id, timestamp, signature)
        res = requests.post(url=url, data=json.dumps(data))
        # r = res
        res = json.loads(res.content)
        if res.get('errcode') == 0:  # 避免user_info为空时出现异常
            unionid = res.get('user_info').get('unionid')
            user_id = cls.get_userid_by_unionid(access_token, unionid)
            # 根据user_id从缓存读取用户名
            user_name = Cache.get_value(key=user_id)
            # 缓存中不存在对应值，通过接口获取
            if not user_name:
                user_name_zh = cls.get_user_info(access_token, user_id).get('name_zh')
            else:
                user_name_zh = Cache.get_value(key=user_name).get('name_zh')
            return user_name_zh
        else:
            # return r
            return None

    @staticmethod
    def get_userid_by_unionid(access_token, unionid):
        """根据unionid获取用户userid"""
        url = 'https://oapi.dingtalk.com/user/getUseridByUnionid?access_token={}&unionid={}'.format(access_token,
                                                                                                    unionid)
        res = requests.get(url)
        res = json.loads(res.content)
        return res.get('userid')

    @staticmethod
    def get_access_token(app_key=APP_KEY, app_secret=APP_SECRET):
        """access_token，进行缓存（钉钉默认7200秒失效，缓存时间小于该值）"""
        access_token = Cache.get_value('access_token')
        if not access_token:
            url = 'https://oapi.dingtalk.com/gettoken?appkey={}&appsecret={}'.format(app_key, app_secret)
            res = requests.get(url)
            access_token = json.loads(res.content).get('access_token')
            Cache.set_value(value=access_token, key='access_token')
        return access_token

    @staticmethod
    def get_user_id_list(access_token, dep_id):
        """根据部门ID获取该部门内所有员工id"""
        url = 'https://oapi.dingtalk.com/user/getDeptMember?access_token={}&deptId={}'.format(access_token, dep_id)
        res = requests.get(url)
        res = json.loads(res.content)
        user_id_list = res.get('userIds')
        return user_id_list

    @classmethod
    def save_user_list(cls, access_token):
        """获取所有部门id，并根据部门id，获取所有部门下员工id，去重后保存所有员工信息到缓存中，键为用户名拼音"""
        # department_list = Cache.read_from_cache('department')
        # if not department_list:
        url = 'https://oapi.dingtalk.com/department/list?access_token={}'.format(access_token)
        res = requests.get(url)
        res = json.loads(res.content)
        department_list = []
        user_list = []
        user_name_list = []

        for each in res.get('department'):
            department_list.append(each.get('id'))
            # # 对所有部门id进行缓存，减少查询时间
            # Cache.write_onetime_cache(value=department_list, key='department', key_time_id=2)   # 默认缓存一周
            user_list.extend(cls.get_user_id_list(access_token, each.get('id')))
            user_list = list(set(user_list))

        for each_id in user_list:
            user_info = cls.get_user_info(access_token, each_id)
            if user_info:
                # 用户名拼音作为缓存key
                Cache.set_value(value=user_info, key=user_info.get('name'), key_time_id=1)

                # 更新用户头像，并缓存本地url
                # file_path = STATICFILES_DIRS[0] + '/images/'
                # file_name = user_info.get('name') + '_avatar.png'
                # # 本地保存钉钉头像
                # save_img(img_url=user_info.get('avatar'), file_name=file_name, file_path=file_path)
                # # 缓存头像本地链接
                # Cache.set_value(value=(STATIC_URL + 'images/' + file_name), key=user_info.get('name') + '_avatar',
                #                 key_time_id=2)

                # 用户userid作为缓存key
                Cache.set_value(value=user_info.get('name'), key=user_info.get('userid'), key_time_id=1)
                user_name_list.append(user_info.get('name'))
        return user_name_list

    @classmethod
    def get_user_info(cls, access_token, userid):
        """从钉钉接口获取用户详细信息，并返回用户名拼音、id、头像等信息"""
        url = 'https://oapi.dingtalk.com/user/get?access_token={}&userid={}'.format(access_token, userid)
        res = requests.get(url)
        res = json.loads(res.content)
        user_info = {}
        if res.get('errmsg') == 'ok':
            user_info['name'] = user_process.han_to_pinyin(res.get('name'))  # 姓名拼音，用作缓存key
            user_info['name_zh'] = res.get('name')     # 姓名汉字，用于校验钉钉用户和前端展示
            user_info['userid'] = res.get('userid')
            user_info['avatar'] = res.get('avatar')  # 钉钉头像

        return user_info

    @classmethod
    def corp_conversation(cls, username, vuln, access_token, msg, user_name_list, agent_id=AGENT_ID, dept_id_list=None,
                          to_all_user=False):
        """工作通知推送，参数说明见文档https://ding-doc.dingtalk.com/doc#/serverapi2/pgoxpy/e2262dad"""
        url = 'https://oapi.dingtalk.com/topapi/message/corpconversation/asyncsend_v2?access_token={}'.format(
            access_token)
        data = {}
        userid_list = ''
        for name in user_name_list:
            user_info = Cache.get_value(key=user_process.han_to_pinyin(name))
            # 缓存查询不到，用户不存在
            if not user_info:
                # cls.save_user_list(access_token=access_token)
                # 用户不存在, 钉钉接口不会判断不存在的用户，强制中断派发请求
                return {'errcode': -1, 'result': '用户{}不存在'.format(name)}
            userid_list = userid_list + (user_info.get('userid') + ',')

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
        tasks.send_conversation(url, data, username, user_name_list, vuln)
        # tasks.send_conversation.delay(url, data, username, user_name_list, vuln)
        return {'errcode': 0, 'result': '漏洞已派发'}

    @classmethod
    def alert_conversation(cls, access_token, msg, user_name_list, agent_id=AGENT_ID, dept_id_list=None,
                          to_all_user=False):
        """普通卡片告警推送，参数说明见文档https://ding-doc.dingtalk.com/doc#/serverapi2/pgoxpy/e2262dad"""
        url = 'https://oapi.dingtalk.com/topapi/message/corpconversation/asyncsend_v2?access_token={}'.format(
            access_token)
        data = {}
        userid_list = ''
        for name in user_name_list:
            user_info = Cache.get_value(key=name)
            # 缓存查询不到，用户不存在
            if not user_info:
                # 用户不存在, 钉钉接口不会判断不存在的用户，强制中断派发请求
                return {'errcode': -1, 'result': '用户{}不存在'.format(name)}
            userid_list = userid_list + (user_info.get('userid') + ',')

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
        res = requests.post(url=url, data=msg)
        res = json.loads(res.content)
        # res = {'errcode': 0, 'task_id': 232719853185, 'request_id': '3x1qbs76ef3k'}
        if res.get('errcode') == 0:
            return {'errcode': res.get('errcode'), 'result': '告警发送成功'}
        return {'errcode': res.get('errcode'), 'result': '告警发送失败'}