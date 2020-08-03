# coding:utf-8
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from .. import models, forms, tasks
from SeMFSetting.views import paging
from django.http import JsonResponse
import time
from django.utils.html import escape
from SeMF.redis import Cache
from RBAC.service.user_process import get_user_area, username_list_identify

# Create your views here.

VULN_LEAVE = {
    '0': '信息',
    '1': '低危',
    '2': '中危',
    '3': '高危',
    '4': '紧急'
}
VULN_STATUS = {
    '0': '已忽略',
    '1': '已修复',
    '2': '待修复',
    '3': '漏洞重现',
    '4': '修复中',
    '5': '已派发',
    '6': '修复完成',
}


@login_required
@csrf_protect
def vuln_change_status(request, vuln_id):
    user = request.user
    error = ''
    if user.is_superuser:
        vuln = get_object_or_404(models.Vulnerability_scan, vuln_id=vuln_id)
        is_admin = True
    else:
        res = get_user_area(user)
        is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
        if is_admin:
            vuln = get_object_or_404(models.Vulnerability_scan, vuln_id=vuln_id)
        else:
            vuln = get_object_or_404(models.Vulnerability_scan, vuln_asset__asset_area__in=user_area_list,
                                     vuln_id=vuln_id)

    if vuln:
        if request.method == 'POST':
            form = forms.Vuln_action_form(request.POST, instance=vuln)
            if form.is_valid():
                if not is_admin and (form.cleaned_data['fix_status'] in ['1', '3']):
                    error = '仅允许更改为"待修复"，"修复中"，"已忽略"'
                else:
                    if vuln.fix_status == '5':      # 修改为已派发时，重置漏洞受理人
                        vuln.process_user = None
                        vuln.save()
                    form.save()
                    error = '更改成功'
            else:
                error = '请检查参数'
        else:
            form = forms.Vuln_action_form(instance=vuln)

    else:
        error = '请检查参数'
    return render(request, 'formupdate.html', {'form': form, 'post_url': 'vulnfix', 'argu': vuln_id, 'error': error})


@login_required
@csrf_protect
def vuln_update(request, vuln_id):
    user = request.user
    error = ''
    # 超管和管理员组具备权限
    if user.is_superuser or get_user_area(user).get('is_admin'):
        vuln = get_object_or_404(models.Vulnerability_scan, vuln_id=vuln_id)
        if vuln:
            if request.method == 'POST':
                form = forms.Vuln_edit_form(request.POST, instance=vuln)
                if form.is_valid():
                    form.save()
                    error = '更改成功'
                else:
                    error = '请检查参数'
            else:
                form = forms.Vuln_edit_form(instance=vuln)
        else:
            error = '请检查参数'
    else:
        error = '权限错误'
    return render(request, 'formupdate.html', {'form': form, 'post_url': 'vulnupdate', 'argu': vuln_id, 'error': error})


@login_required
@csrf_protect
def vulncreate(request, asset_id):
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
        form = forms.Vuln_edit_form(request.POST)
        if form.is_valid():
            try:
                num = models.Vulnerability_scan.objects.latest('id').id
            except Exception:
                num = 0
            num = num + 1
            vuln_name = form.cleaned_data['vuln_name']
            cve_name = form.cleaned_data['cve_name']
            leave = form.cleaned_data['leave']
            introduce = form.cleaned_data['introduce']
            vuln_info = form.cleaned_data['vuln_info']
            scopen = form.cleaned_data['scopen']
            fix = form.cleaned_data['fix']
            vuln_id = str(asset.asset_type.id) + time.strftime('%Y%m%d', time.localtime(time.time())) + str(num)
            vuln_type = asset.asset_type.name
            res = models.Vulnerability_scan.objects.get_or_create(
                vuln_name=vuln_name,
                cve_name=cve_name,
                vuln_type=vuln_type,
                leave=leave,
                introduce=introduce,
                vuln_info=vuln_info,
                scopen=scopen,
                fix=fix,
                vuln_asset=asset,
            )
            vuln = res[0]
            if vuln.vuln_id == vuln_id:
                if vuln.fix_status == '1':
                    vuln.fix_status = '3'
            else:
                vuln.vuln_id = vuln_id
                if leave == '0':
                    vuln.fix_status = '0'
                vuln.fix_status = '2'
            vuln.save()
            error = '添加成功'
        else:
            error = '请检查输入'
    else:
        form = forms.Vuln_edit_form()
    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'vulncreate', 'argu': asset_id, 'error': error})


@login_required
def vulndetails(request, vuln_id):
    user = request.user
    if user.is_superuser:
        vuln = get_object_or_404(models.Vulnerability_scan, vuln_id=vuln_id)
    else:
        res = get_user_area(user)
        is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
        if is_admin:
            vuln = get_object_or_404(models.Vulnerability_scan, vuln_id=vuln_id)
        else:
            vuln = get_object_or_404(models.Vulnerability_scan, vuln_asset__asset_area__in=user_area_list,
                                     vuln_id=vuln_id)
        # vuln = get_object_or_404(models.Vulnerability_scan, vuln_asset__asset_user=user, vuln_id=vuln_id)
    return render(request, 'VulnManage/vulndetails.html', {'vuln': vuln})


@login_required
def vulnview(request):
    return render(request, 'VulnManage/vulnlist.html')


@login_required
@csrf_protect
def vulntablelist(request):
    user = request.user
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    key = request.POST.get('key')
    if not key:
        key = ''
    v_key = request.POST.get('v_key')
    if not v_key:
        v_key = ''
    leave = request.POST.get('leave')
    if not leave:
        leave = ''
    fix_status = request.POST.get('fix_status')
    if not fix_status:
        fix_status = ''

    if user.is_superuser:
        vuln_list = models.Vulnerability_scan.objects.filter(
            vuln_asset__asset_key__icontains=key,
            vuln_name__icontains=v_key,
            leave__icontains=leave,
            fix_status__icontains=fix_status,
            leave__gte=1,
        ).order_by('-fix_status', '-leave')
    else:
        # 获取用户所在项目组所有
        res = get_user_area(user)
        is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')

        if is_admin:
            vuln_list = models.Vulnerability_scan.objects.filter(
                vuln_asset__asset_key__icontains=key,
                vuln_name__icontains=v_key,
                leave__icontains=leave,
                fix_status__icontains=fix_status,
                leave__gte=1,
            ).order_by('-fix_status', '-leave')
        else:
            # user_area_list 则查询不到数据
            vuln_list = models.Vulnerability_scan.objects.filter(
                vuln_asset__asset_area__in=user_area_list,  # 根据项目ID进行筛选
                vuln_asset__asset_key__icontains=key,
                vuln_name__icontains=v_key,
                leave__icontains=leave,
                fix_status__icontains=fix_status,
                leave__gte=1,
            ).order_by('-fix_status', '-leave')

    total = vuln_list.count()
    vuln_list = paging(vuln_list, rows, page)
    data = []
    for vuln_item in vuln_list:
        dic = {}
        dic['vuln_id'] = escape(vuln_item.vuln_id)
        dic['vuln_info'] = escape(vuln_item.vuln_info)
        dic['vuln_name'] = escape(vuln_item.vuln_name)
        dic['vuln_type'] = escape(vuln_item.vuln_type)
        dic['leave'] = escape(VULN_LEAVE[vuln_item.leave])
        dic['fix_status'] = escape(VULN_STATUS[vuln_item.fix_status])
        dic['update_data'] = escape(vuln_item.update_data)
        dic['asset'] = escape(vuln_item.vuln_asset.asset_key)
        dic['asset_id'] = escape(vuln_item.vuln_asset.asset_id)
        dic['process_user'] = escape(vuln_item.process_user if vuln_item.process_user else '无')
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "漏洞列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
@csrf_protect
def vulnlist_change_status(request):
    vuln_id_list = request.POST.get('vuln_id_list')
    vuln_id_list_key = Cache.set_value(vuln_id_list)
    models.VulnlistFix.objects.get_or_create(
        id=1,
    )
    return JsonResponse({'v_id': vuln_id_list_key})


@login_required
@csrf_protect
def vulnlist_change_status_id(request, v_id):
    user = request.user
    if user.is_superuser:
        is_admin = True
    else:
        is_admin = get_user_area(user).get('is_admin')
    vulnlist = get_object_or_404(models.VulnlistFix, id=1)
    error = ''
    if request.method == 'POST':
        if is_admin:
            form = forms.Vulnlist_action_form(request.POST, instance=vulnlist)
        else:
            form = forms.Vulnlist_action_form2(request.POST, instance=vulnlist)
        if form.is_valid():
            fix_status = form.cleaned_data['fix_status']
            form.save()
            tasks.vulnlist_save_status(v_id, fix_status)
            error = '操作成功'
        else:
            error = '请检查输入'
    else:
        if is_admin:
            form = forms.Vulnlist_action_form(instance=vulnlist)
        else:
            form = forms.Vulnlist_action_form2(instance=vulnlist)

    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'vulnlistfixid', 'argu': v_id, 'error': error})


@login_required
@csrf_protect
def vulnlist_assign(request, v_id):
    user = request.user
    if user.is_superuser:
        is_admin = True
    else:
        is_admin = get_user_area(user).get('is_admin')
    error = ''
    if request.method == 'POST':
        if is_admin:
            form = forms.Vulnlist_assign(request.POST)
            if form.is_valid():

                res = username_list_identify(form.cleaned_data['assign_user'])
                error = res.get('result')
                username_list = res.get('username_list')
                if error == 0:  # 进行钉钉漏洞派发
                    error = tasks.vulnlist_assign(v_id, user, username_list).get('result')
            else:
                error = '请检查输入'
        else:
            # form = forms.Vulnlist_assign(request.POST)
            error = '权限错误'
            form = forms.Vulnlist_assign()

    else:
        form = forms.Vulnlist_assign()

    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'vulnassign', 'argu': v_id, 'error': error})
