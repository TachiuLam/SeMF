# -*- coding: utf-8 -*-
# tachiu lam
# techaolin@gmail.com
# 2020/7/9 2:59 下午
# PyCharm
from django.urls import path
from .views import views, cnvdviews

urlpatterns = [
    path('user/', views.vulnview, name='vulnview'),
    path('user/list/', views.vulntablelist, name='vulnlist'),
    # path('user/listfix/',views.vulnfixlist,name='vulnlistfix'),
    path('user/listfix/', views.vulnlist_change_status, name='vulnlistfix'),
    path('user/listfixid/<str:v_id>', views.vulnlist_change_status_id, name='vulnlistfixid'),
    path('user/fix/<str:vuln_id>/', views.vuln_change_status, name='vulnfix'),
    path('user/details/<str:vuln_id>/', views.vulndetails, name='vulndetails'),
    path('user/files/upload/', views.vuln_files, name='reportupload'),

    path('cnvd/', cnvdviews.cnvdvuln_view, name='cnvdvulnview'),
    path('cnvd/list/', cnvdviews.cnvdvulntablelist, name='cnvdvulnlist'),
    path('cnvd/update/<str:vuln_id>', cnvdviews.cnvdvuln_update, name='cnvdvulnupdate'),
    path('cnvd/details/<str:vuln_id>', cnvdviews.cnvdvulndetails, name='cnvdvulndetails'),
    path('cnvd/vulnrenew/', cnvdviews.renew, name='cnvdvulnrenew'),
    path('cnvd/create/', cnvdviews.cnvdvulncreate, name='cnvdvulncreate'),

    path('manage/create/<str:asset_id>/', views.vulncreate, name='vulncreate'),
    path('manage/update/<str:vuln_id>/', views.vuln_update, name='vulnupdate'),
    path('manage/assign/<str:v_id>', views.vulnlist_assign, name='vulnassign'),
]
