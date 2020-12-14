# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechoa@yingzi.com
# 2020/6/4 18:00

from django.urls import path
from . import views


urlpatterns = [
    path('upload/', views.report_upload, name='report_upload'),
    path('info/', views.api_info, name='apiinfo'),
    path('dingtalk/', views.ding_vuln_view, name='dingtalk_view'),
    path('dingtalk/list/', views.ding_vuln_list, name='dingtalk_vulnlist'),
    path('dingtalk/process/', views.ding_vuln_process, name='dingtalk_process'),
    path('dingtalk/detail_id/<str:v_detail_id>/', views.ding_vuln_detail, name='dingtalk_detail_id'),
    path('dingtalk/detail/', views.ding_vuln_token, name='dingtalk_detail'),
    path('nat/upload/',views.nat_upload,name='nat_upload'),
    path('harbor/webhook/', views.harbor_webhook, name="harbor_webhook"),
]
