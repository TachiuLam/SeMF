from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.utils.html import escape
from SeMF.settings import MEDIA_API, MEDIA_TYPE, APP_KEY, APP_SECRET, AUTH_APP_ID, AUTH_APP_SECRET
from SeMF.views import permission_denied
from SeMF.redis import Cache
from SeMFSetting.views import paging
from RBAC.service.user_process import get_user_area
from VulnManage.models import Vulnerability_scan
from VulnManage.views.views import VULN_STATUS, VULN_LEAVE
from API.Functions.api_auth import JWT
from API.Functions.rsas import RSAS
from API.Functions.dinktalk import DinkTalk
import shutil
import os
import json


# Create your views here.
@csrf_exempt
@require_http_methods(['POST'])
def report_upload(request):
    """漏洞报告上传接口"""
    # print(request.FILES)
    token = request.META.get('HTTP_AUTHORIZATION')
    user = JWT.decode_jwt(token).get('user')
    if user and User.objects.filter(username=user).first():
        if request.POST.get('type') == MEDIA_TYPE[0]:  # rsas处理漏扫结果
            file = request.FILES.get('file', None)
            # 保存报告
            if file and file.name.endswith('.zip'):  # 只接收.zip后缀文件
                with open(MEDIA_API + '/' + file.name, 'wb+') as dst:  # 打开特定的文件进行二进制的写操作
                    for chunk in file.chunks():  # 分块写入文件
                        dst.write(chunk)
                # 处理报告
                # 按文件名判断漏洞报告类型，服务器/办公设备/容器等
                report_type = RSAS.report_type(dst.name)
                file_list = RSAS.unzip_file(dst.name, MEDIA_API)
                for f in file_list:
                    RSAS.report_main(f, report_type)
                # 清空文件夹
                shutil.rmtree(MEDIA_API)
                os.mkdir(MEDIA_API)
                return JsonResponse({'success': 'success upload',
                                     'body': file.name,
                                     })
            return JsonResponse({'success': 'success upload',
                                 'body': 'file no found',
                                 })
    return JsonResponse({'error': 'permission deny'})


@login_required()
def api_info(request):
    """API文档接口"""
    user = request.user
    token = JWT.generate_jwt(user=user)
    return render(request, 'API/apiinfo.html', {'info': {'token': token}})


@csrf_exempt
def ding_vuln_view(request):
    """钉钉漏洞首页"""
    code = request.GET.get('code')
    # 权限判断
    # if not code:
    #     return permission_denied(request)
    # access_token = DinkTalk.get_access_token(APP_KEY, APP_SECRET)
    # user_name = DinkTalk.get_user_name_by_code(code, access_token, AUTH_APP_ID, AUTH_APP_SECRET)
    # if not user_name:
    #     return permission_denied(request)
    # user_name = 'lintechao'     # 调试用
    # context = {}
    # # 构造token返回
    # token = Cache.get_value(key='tk_' + user_name)
    # if not token:
    #     token = JWT.generate_jwt('tk_' + user_name)
    #     Cache.set_value(token, 'tk_' + user_name, 3)
    # token = token.split('Token ')[1]
    # context['token'] = json.dumps(token)
    # return render(request, 'API/dingtalk_vulnlist.html', context)
    return render(request, 'API/dingtalk_vulnlist.html')


@csrf_exempt
def ding_vuln_list(request):
    """钉钉漏洞数据接口"""
    resultdict = {}
    # token = request.POST.get('token')
    # if not code:
    #     return permission_denied(request)
    # access_token = DinkTalk.get_access_token(APP_KEY, APP_SECRET)
    # user_name = DinkTalk.get_user_name_by_code(code, access_token, AUTH_APP_ID, AUTH_APP_SECRET)
    # if not user_name:
    #     return permission_denied(request)
    # user_name = JWT.decode_jwt(token).get('user')
    page = request.POST.get('page')
    rows = request.POST.get('limit')
    # res = get_user_area(user_name)
    # is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
    is_admin = True  # 调试用
    user_area_list = None
    # 返回状态不为“已修复”的漏洞
    if is_admin:
        vuln_list = Vulnerability_scan.objects.exclude(
            fix_status__icontains='1',
            leave__gte=1,
        ).order_by('-fix_status', '-leave')
    else:
        vuln_list = Vulnerability_scan.objects.filter(
            vuln_asset__asset_area__in=user_area_list,  # 根据项目ID进行筛选
            leave__gte=1,
        ).exclude(fix_status__icontains='1', ).order_by('-fix_status', '-leave')

    total = vuln_list.count()
    vuln_list = paging(vuln_list, rows, page)
    data = []
    for vuln_item in vuln_list:
        dic = {}
        dic['vuln_id'] = escape(vuln_item.vuln_id)
        dic['vuln_name'] = escape(vuln_item.vuln_name)
        dic['leave'] = escape(VULN_LEAVE[vuln_item.leave])
        dic['fix_status'] = escape(VULN_STATUS[vuln_item.fix_status])
        dic['asset'] = escape(vuln_item.vuln_asset.asset_key)
        dic['asset_id'] = escape(vuln_item.vuln_asset.asset_id)
        dic['assign_user'] = None
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "漏洞列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@csrf_exempt
def ding_vuln_accept(request):
    """钉钉受理接口"""
    pass


@csrf_exempt
def ding_vuln_detail(request, vuln_id):
    """钉钉漏洞详情页"""
    # token = request.POST.get('token')
    # vuln_id = request.POST.get('vuln_id')
    # user_name = JWT.decode_jwt(token).get('user')
    # res = get_user_area(user_name)
    # is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
    is_admin = True  # 调试用
    if is_admin:
        vuln = get_object_or_404(Vulnerability_scan, vuln_id=vuln_id)
    else:
        user_area_list = None
        vuln = get_object_or_404(Vulnerability_scan, vuln_asset__asset_area__in=user_area_list, vuln_id=vuln_id)
    return render(request, 'VulnManage/vulndetails.html', {'vuln': vuln})
