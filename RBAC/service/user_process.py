# -*- coding: utf-8 -*-
# Tachiu Lam
# techaolin@gamil.com
# 2020/7/7 14:11

from django.contrib.auth.models import User
from pypinyin import lazy_pinyin
from RBAC.models import Area, Profile
from SeMF.settings import MANAGE_TEAM
from SeMF.redis import Cache


def get_user_area(user):
    """
    根据request.user值返回用户所属项目组，判断用户是否属于管理员组
    :param user: request.user
    :return: {'is_admin': is_admin, 'user_area_list': user_area_list}
    """
    # 字符串类型的 user是用户名字字符串，用于钉钉接口
    if isinstance(user, str):
        user_id = User.objects.filter(username=user).values('id').first().get('id')
        user_area = Profile.objects.filter(user_id=user_id).values('area').all()
    else:       # request.user 对象
        # 获取用户所在项目组所有
        user_area = Profile.objects.filter(user=user).values('area').all()
    is_admin = False
    user_area_list = []
    for each in user_area:
        # 判断是否为管理员组
        if Area.objects.filter(id=each.get('area')).values('name').first().get('name') in MANAGE_TEAM:
            is_admin = True
            break
        # 不为安全组则继续执行
        user_area_list.append(each.get('area'))
        is_admin = False
    return {'is_admin': is_admin, 'user_area_list': user_area_list}


def han_to_pinyin(name):
    """将汉字转换为拼音，用于用户名转换"""
    en_name = ''
    en_name_list = lazy_pinyin(name)
    for each in en_name_list:
        en_name += each
    return en_name


def username_list_identify(username_list):

    if not username_list:
        return {'result': '请输入要派发的用户名，多个用户名以中文分号 ；进行分隔'}

    username_list = username_list.replace(' ', '').split('；')    # 以中文字符；为分隔符切割成列表
    for username in username_list:
        if not username:
            return {'result': '请输入合法的用户名，多个用户名以中文分号 ；进行分隔'}
        name = han_to_pinyin(username)
        if not Cache.get_value(key=name):
            return {'result': '用户“{}”不存在, 请输入合法的用户名，多个用户名以中文分号 ；进行分隔'.format(username)}     # 返回中文名
        # 进行漏洞项目和派发用户所属项目组匹配，符合才发送
        # 该功能待需要再添加

    # 所有用户均合法，返回正确码
    return {'result': 0, 'username_list': username_list}
