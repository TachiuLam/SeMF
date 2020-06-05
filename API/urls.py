# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechoa@yingzi.com
# 2020/6/4 18:00

from django.urls import path
from .views import rsas_upload


urlpatterns = [
    path('rsas/', rsas_upload, name='rsas_upload'),
]
