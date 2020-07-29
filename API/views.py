from django.shortcuts import render, get_object_or_404, HttpResponse
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.utils.html import escape
from SeMF.settings import MEDIA_API, MEDIA_TYPE, APP_KEY, APP_SECRET, AUTH_APP_ID, AUTH_APP_SECRET
from SeMF.views import permission_denied, page_not_found
from SeMF.redis import Cache
from SeMFSetting.views import paging
from RBAC.service.user_process import get_user_area, han_to_pinyin
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
    from .tasks import refresh_cache
    refresh_cache()
    user = request.user
    token = JWT.generate_jwt(user=user)
    return render(request, 'API/apiinfo.html', {'info': {'token': token}})


@csrf_exempt
def ding_vuln_view(request):
    """钉钉漏洞首页"""
    code = request.GET.get('code')
    # 权限判断
    if not code:
        return permission_denied(request)
    access_token = DinkTalk.get_access_token(APP_KEY, APP_SECRET)
    user_name_zh = DinkTalk.get_user_name_by_code(code, access_token, AUTH_APP_ID, AUTH_APP_SECRET)
    if not user_name_zh:
        return page_not_found(request)
    # return HttpResponse(user_name_zh)
    # user_name_zh = '林特超'     # 调试用
    context = {}
    # 构造token返回
    token = Cache.get_value(key='tk_' + user_name_zh)       # 注意加密和缓存key为 tk_中文用户名
    if not token:
        token = JWT.generate_jwt('tk_' + user_name_zh)
        Cache.set_value(token, 'tk_' + user_name_zh, 3)
    # token = token.split('Token ')[1]
    context['token'] = json.dumps(token)
    return render(request, 'API/dingtalk_vulnlist.html', context)


@csrf_exempt
def ding_vuln_list(request):
    """钉钉漏洞数据接口"""
    resultdict = {}
    token = request.POST.get('token')
    if not token:
        return permission_denied(request)

    tk_user_name_zh = JWT.decode_jwt(token).get('user')
    if not tk_user_name_zh:
        return page_not_found(request)
    user_name_zh = tk_user_name_zh.split('tk_')[1]
    page = request.POST.get('page')
    rows = request.POST.get('limit')
    user_name = han_to_pinyin(user_name_zh)
    res = get_user_area(user_name)
    is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
    # is_admin = True  # 调试用
    # user_area_list = None

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
        dic['assign_user'] = vuln_item.process_user
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "漏洞列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@require_http_methods(['POST'])
@csrf_exempt
def ding_vuln_process(request):
    """钉钉受理接口"""
    token = request.POST.get('token')
    tk_user_name_zh = JWT.decode_jwt(token).get('user')
    if not tk_user_name_zh:     # 校验token，防止cc攻击，导致缓存空间不足
        return {'error': '非法用户'}
    user_name_zh = tk_user_name_zh.split('tk_')[1]
    vuln_id_list = request.POST.get('vuln_id_list')

    if isinstance(vuln_id_list, list):
        for vuln_id in vuln_id_list:
            # 判断是否有受理权限 漏洞是否已被受理
            if not vuln_to_assign(vuln_id, user_name_zh):
                return {'error': '无受理权限'}
            elif not vuln_to_process(vuln_id):
                return {'error': '{} 漏洞已被受理'.format(vuln_id)}
            vuln = get_object_or_404(Vulnerability_scan, vuln_id=vuln_id)
            vuln.process_user = user_name_zh
            vuln.fix_status = '4'   # 修复中
            return {'error': '已受理'}

    elif isinstance(vuln_id_list, str):
        # 判断是否有受理权限 漏洞是否已被受理
        if not vuln_to_assign(vuln_id_list, user_name_zh):
            return {'error': 'No process permission'}
        elif not vuln_to_process(vuln_id_list):
            return {'error': '{} 漏洞已被受理'.format(vuln_id_list)}
        vuln = get_object_or_404(Vulnerability_scan, vuln_id=vuln_id_list)
        vuln.process_user = user_name_zh
        vuln.fix_status = '4'  # 修复中
        return {'error': '已受理'}
    return {'error': '未知错误，请联系管理员'}


def vuln_to_assign(vuln_id, user_name_zh):
    """根据漏洞id/id列表，判断用户是否属于漏洞派发人员"""
    assign_user_list = Vulnerability_scan.objects.filter(vuln_id=vuln_id).values('assign_user')
    if not assign_user_list:
        return False
    assign_user_list = eval(assign_user_list)       # 将字符产列表转换为列表
    if user_name_zh in assign_user_list:
        return True
    return False


def vuln_to_process(vuln_id):
    """判断漏洞是否已被受理"""
    process_user = Vulnerability_scan.objects.filter(vuln_id=vuln_id).values('process_user')
    if not process_user:
        return True
    return False


@require_http_methods(['POST'])
@csrf_exempt
def ding_vuln_token(request):
    """钉钉漏洞id和token加工形成新v_token"""
    token = request.POST.get('token')
    vuln_id = request.POST.get('vuln_id')
    tk_user_name_zh = JWT.decode_jwt(token).get('user')
    if not tk_user_name_zh:  # 校验token，防止cc攻击，导致缓存空间不足
        return page_not_found(request)

    v_detail_id = 'yz' + vuln_id
    if not Cache.get_value(key=v_detail_id):
        v_token = JWT.generate_jwt(user=tk_user_name_zh, vuln_id=v_detail_id)
        v_detail_id = Cache.set_value(v_token, key=v_detail_id, key_time_id=2)
    return JsonResponse({'v_detail_id': v_detail_id})


@csrf_exempt
def ding_vuln_detail(request, v_detail_id):
    """钉钉漏洞详情页，根据v_detail_id获取token、vuln_id，返回对应漏洞详情"""
    v_token = Cache.get_value(v_detail_id)
    if not v_token:
        return permission_denied(request)
    tk_user_name_zh = JWT.decode_jwt(v_token).get('user')
    user_name_zh = tk_user_name_zh.split('tk_')[1]
    vuln_id = JWT.decode_jwt(v_token).get('v_detail_id').split('yz')[1]
    user_name = han_to_pinyin(user_name_zh)
    res = get_user_area(user_name)
    is_admin, user_area_list = res.get('is_admin'), res.get('user_area_list')
    # is_admin = True  # 调试用
    # user_area_list = None
    if is_admin:
        vuln = get_object_or_404(Vulnerability_scan, vuln_id=vuln_id)
    else:
        vuln = get_object_or_404(Vulnerability_scan, vuln_asset__asset_area__in=user_area_list, vuln_id=vuln_id)
    return render(request, 'VulnManage/vulndetails.html', {'vuln': vuln})
