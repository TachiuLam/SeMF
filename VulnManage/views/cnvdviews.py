# coding:utf-8
'''
Created on 2018年5月21日

@author: yuguanc
'''
from django.shortcuts import render, get_object_or_404, HttpResponseRedirect
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from .. import models, forms
from SeMFSetting.views import paging
from django.http import JsonResponse
from django.db.models import Q, Count
from ..tasks import parse_cnvdxml
from SeMF.settings import MEDIA_ROOT
import os
from django.utils.html import escape
from RBAC.service.user_process import get_user_area
import time

VULN_LEAVE = {
    '0': '信息',
    '1': '低危',
    '2': '中危',
    '3': '高危',
    '4': '紧急'
}

@login_required
@csrf_protect
def renew(request):
    user = request.user
    error = ''
    if user.is_superuser or get_user_area(user).get('is_admin'):
        if request.method == 'POST':
            form = forms.Cnvd_file_form(request.POST, request.FILES)
            if form.is_valid():
                file = form.cleaned_data['file']
                if file.name.lower().endswith('.xml'):
                    if file.content_type == 'text/xml':
                        file_list = models.Cnvdfiles.objects.get_or_create(
                            file=file,
                            title=file.name,
                        )
                        for file in file_list:
                            filepath = os.path.join(MEDIA_ROOT, 'cnvd', file.title)
                            parse_cnvdxml.delay(filepath)
                            break
                        error = '更新成功'
                    else:
                        error = '文件错误'
                else:
                    error = '文件错误'
            else:
                error = '文件错误'
        else:
            form = forms.Cnvd_file_form()
            return render(request, 'formedit.html', {'form': form, 'post_url': 'cnvdvulnrenew', 'title': '同步漏洞库'})
    else:
        error = '权限不足'
    return render(request, 'error.html', {'error': error})


@login_required
def cnvdvulndetails(request, vuln_id):
    vuln = get_object_or_404(models.Vulnerability, vuln_id=vuln_id)
    return render(request, 'VulnManage/cnvdvulndetails.html', {'vuln': vuln})


@login_required
@csrf_protect
def cnvdvuln_update(request, vuln_id):
    user = request.user
    error = ''
    if user.is_superuser or get_user_area(user).get('is_admin'):
        vuln = get_object_or_404(models.Vulnerability, vuln_id=vuln_id)
        if request.method == 'POST':
            form = forms.Cnvd_vuln_form(request.POST, instance=vuln)
            if form.is_valid():
                form.save()
                error = '修改成功'
        else:
            form = forms.Cnvd_vuln_form(instance=vuln)
        return render(request, 'formupdate.html',
                      {'form': form, 'post_url': 'cnvdvulnupdate', 'argu': vuln_id, 'error': error})
    else:
        error = '权限错误'
        return render(request, 'error.html', {'error': error})


@login_required
def cnvdvuln_view(request):
    return render(request, 'VulnManage/cnvdvulnlist.html')


@login_required
@csrf_protect
def cnvdvulntablelist(request):
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    name = request.POST.get('name')
    if not name:
        name = ''

    leave = request.POST.get('leave')
    if not leave:
        leave = ''

    vuln_list = models.Vulnerability.objects.filter(
        Q(vuln_name__icontains=name) | Q(cve_name__icontains=name)
    ).filter(leave__icontains=leave).order_by('-update_data')

    total = vuln_list.count()
    vuln_list = paging(vuln_list, rows, page)
    data = []
    for vuln_item in vuln_list:
        dic = {}
        dic['vuln_id'] = escape(vuln_item.vuln_id)
        dic['cve_name'] = escape(vuln_item.cve_name)
        dic['vuln_name'] = escape(vuln_item.vuln_name)
        dic['leave'] = escape(VULN_LEAVE[vuln_item.leave])
        dic['update_data'] = escape(vuln_item.update_data)
        count = models.Vulnerability_scan.objects.filter(vuln_name=vuln_item.vuln_name).values('vuln_name').annotate(
            number=Count('id'))
        if not count:
            dic['count'] = '0'
        else:
            dic['count'] = str(count.get('number'))
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "漏洞列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)

@login_required
@csrf_protect
def cnvdvulncreate(request):
    user = request.user
    error = ''
    if user.is_superuser or get_user_area(user).get('is_admin'):
        if request.method == 'POST':
            form = forms.Cnvd_vuln_form(request.POST)
            if form.is_valid():
                try:
                    num = models.Vulnerability.objects.latest('id').id
                except Exception:
                    num = 0
                num = num + 1
                vuln_id = time.strftime('%Y%m%d', time.localtime(time.time())) + str(num)
                vuln_name = form.cleaned_data['vuln_name']
                cve_name = form.cleaned_data['cve_name']
                leave = form.cleaned_data['leave']
                introduce = form.cleaned_data['introduce']
                note = form.cleaned_data['note']
                fix = form.cleaned_data['fix']
                res = models.Vulnerability.objects.get_or_create(
                    vuln_id = vuln_id,
                    vuln_name=vuln_name,
                    cve_name=cve_name,
                    leave=leave,
                    introduce=introduce,
                    note=note,
                    fix=fix,
                )
                vuln = res[0]
                vuln.save()
                error = '添加成功'
            else:
                error = '请检查输入'
        else:
            form = forms.Cnvd_vuln_form()
        return render(request, 'formedit.html',
                      {'form': form, 'post_url': 'cnvdvulncreate','error': error})
    else:
        error = '权限错误'
        return render(request, 'error.html', {'error': error})
