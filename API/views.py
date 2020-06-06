from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import HttpResponse, render
from django.contrib.auth.decorators import login_required
from SeMF.settings import MEDIA_API, SESSION_PERMISSION_URL_KEY, REGEX_URL
from .Functions.api_auth import JWT


# Create your views here.
@csrf_exempt
@require_http_methods(['GET', 'POST'])
def rsas_upload(request):
    """绿盟漏扫结果上传"""
    if request.method == 'POST':
        data = request.content_type
        print(request.FILES)
        print(data)
        file = request.FILES.get('file', None)
        if file:
            file_name = file.name
            with open(MEDIA_API + '/' + file_name, 'wb+') as dst:  # 打开特定的文件进行二进制的写操作
                for chunk in file.chunks():  # 分块写入文件
                    dst.write(chunk)
        return JsonResponse({'success': 'success upload',
                             'data': 'file_name',
                             })

    return JsonResponse({'error': 'not allow'})


@login_required()
def api_info(request):
    user = request.user
    token = JWT.generate_jwt(user=user)
    return render(request, 'API/apiinfo.html', {'info': {'token': token, 'method': 'method'}})
