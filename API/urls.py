# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechoa@yingzi.com
# 2020/6/4 18:00

from django.urls import path
from . import views


urlpatterns = [
    path('upload/', views.report_upload, name='report_upload'),
    path('info/', views.api_info, name='apiinfo'),
    path('dingtalk/', views.ding_vuln_detail)
]
