# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechoa@yingzi.com
# 2020/6/4 18:00

from django.urls import path
from . import views


urlpatterns = [
    path('rsas/', views.rsas_upload, name='rsas_upload'),
    path('info/', views.api_info, name='apiinfo'),
]
