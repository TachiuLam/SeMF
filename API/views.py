from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from SeMF.settings import MEDIA_API, MEDIA_TYPE, SESSION_PERMISSION_URL_KEY, REGEX_URL
from API.Functions.api_auth import JWT
from API.Functions.rsas import RSAS
import shutil
import os


# Create your views here.
@csrf_exempt
@require_http_methods(['POST'])
def report_upload(request):
    """漏洞报告上传"""
    # print(request.FILES)
    token = request.META.get('HTTP_AUTHORIZATION')
    user = JWT.decode_jwt(token).get('user')
    if user and User.objects.filter(username=user).first():
        if request.POST.get('type') == MEDIA_TYPE[0]:  # rsas处理漏扫结果
            file = request.FILES.get('file', None)
            # 保存报告
            if file and file.name.endswith('.zip'):  # 只接收.zip后缀文件
                with open(MEDIA_API + '/' + 'rsas.zip', 'wb+') as dst:  # 打开特定的文件进行二进制的写操作
                    for chunk in file.chunks():  # 分块写入文件
                        dst.write(chunk)
                # 处理报告
                file_list = RSAS.unzip_file(dst.name, MEDIA_API)
                for f in file_list:
                    RSAS.report_main(f)
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
    user = request.user
    token = JWT.generate_jwt(user=user)
    return render(request, 'API/apiinfo.html', {'info': {'token': token, 'method': {'type': 'rsas',  # 目前支持rsas
                                                                                    'file': 'file'}}})
