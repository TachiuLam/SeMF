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
def portcreate(request, asset_id):
    user = request.user
    error = ''
    if user.is_superuser:
        asset = get_object_or_404(models.Asset, asset_id=asset_id)
    else:
        res = get_user_area(user)
        is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
        if is_admin:
            asset = get_object_or_404(models.Asset, asset_id=asset_id)
        else:
            asset = get_object_or_404(models.Asset, asset_area__in=user_area_list, asset_id=asset_id)
    if request.method == 'POST':
        form = forms.Asset_port_info(request.POST)
        if form.is_valid():
            port = form.cleaned_data['port']
            name = form.cleaned_data['name']
            product = form.cleaned_data['product']
            version = form.cleaned_data['version']
            port_info = form.cleaned_data['port_info']
            models.Port_Info.objects.get_or_create(
                port=port,
                name=name,
                product=product,
                version=version,
                port_info=port_info,
                asset=asset
            )
            error = '添加成功'
        else:
            error = '请检查输入'
    else:
        form = forms.Asset_port_info()
    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'portcreate', 'argu': asset_id, 'error': error})


@login_required
@csrf_protect
def portupdate(request, port_id):
    user = request.user
    error = ''
    if user.is_superuser:
        port = get_object_or_404(models.Port_Info, id=port_id)
    else:
        res = get_user_area(user)
        is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
        if is_admin:
            port = get_object_or_404(models.Port_Info, id=port_id)
        else:
            port = get_object_or_404(models.Port_Info, asset__asset_area__in=user_area_list, id=port_id)
    if request.method == 'POST':
        form = forms.Asset_port_info(request.POST, instance=port)
        if form.is_valid():
            form.save()
            error = '端口信息已更新'
        else:
            error = '请检查输入'
    else:
        form = forms.Asset_port_info(instance=port)
    return render(request, 'formupdate.html', {'form': form, 'post_url': 'portupdate', 'argu': port_id, 'error': error})


@login_required
def portdelete(request, port_id):
    user = request.user
    error = ''
    if user.is_superuser:
        port = get_object_or_404(models.Port_Info, id=port_id)
    else:
        res = get_user_area(user)
        is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
        if is_admin:
            port = get_object_or_404(models.Port_Info, id=port_id)
        else:
            port = get_object_or_404(models.Port_Info, asset__asset_area__in=user_area_list, id=port_id)
    if port:
        port.delete()
        error = '删除成功'
    else:
        error = '非法参数'
    return JsonResponse({'error': error})
