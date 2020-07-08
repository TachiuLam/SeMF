# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechoa@yingzi.com
# 2020/7/7 14:11

from RBAC.models import Area, Profile
from SeMF.settings import MANAGE_TEAM


def get_user_area(user):
    """
    根据request.user值返回用户所属项目组，判断用户是否属于管理员组
    :param user: request.user
    :return: {'is_admin': is_admin, 'user_area_list': user_area_list}
    """
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
