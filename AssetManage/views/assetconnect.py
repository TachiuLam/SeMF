# coding:utf-8
'''
Created on 2018年5月18日

@author: yuguanc
'''
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from .. import models, forms
from django.http import JsonResponse
from RBAC.service.user_process import get_user_area


@login_required
@csrf_protect
def assetconnectcreate(request, asset_id):
    user = request.user
    error = ''
    if request.method == 'POST':
        form = forms.Asset_connect_form(request.POST)
        if form.is_valid():
            asset_key = form.cleaned_data['asset_key']
            if user.is_superuser:
                asset = get_object_or_404(models.Asset, asset_id=asset_id)
                asset_get = get_object_or_404(models.Asset, asset_key=asset_key)
            else:
                res = get_user_area(user)
                is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
                if is_admin:
                    asset = get_object_or_404(models.Asset, asset_id=asset_id)
                    asset_get = get_object_or_404(models.Asset, asset_key=asset_key)
                else:
                    asset = get_object_or_404(models.Asset, asset_area__in=user_area_list, asset_id=asset_id)
                    asset_get = get_object_or_404(models.Asset, asset_area__in=user_area_list, asset_key=asset_key)
            asset.asset_connect.add(asset_get)
            asset.save()
            error = '关联成功'
        else:
            error = '请检查输入'
    else:
        form = forms.Asset_connect_form()
    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'assetconnectcreate', 'argu': asset_id, 'error': error})


@login_required
def assetconnectdelete(request, asset_id, assetconnect_id):
    user = request.user
    error = ''
    if user.is_superuser:
        asset = get_object_or_404(models.Asset, asset_id=asset_id)
        asset_get = get_object_or_404(models.Asset, asset_id=assetconnect_id)
    else:
        res = get_user_area(user)
        is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
        if is_admin:
            asset = get_object_or_404(models.Asset, asset_id=asset_id)
            asset_get = get_object_or_404(models.Asset, asset_id=assetconnect_id)
        else:
            asset = get_object_or_404(models.Asset, asset_area__in=user_area_list, asset_id=asset_id)
            asset_get = get_object_or_404(models.Asset, asset_area__in=user_area_list, asset_id=assetconnect_id)
    if asset_get:
        asset.asset_connect.remove(asset_get)
        asset.save()
        error = '删除成功'
    else:
        error = '非法参数'
    return JsonResponse({'error': error})
