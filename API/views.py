from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from SeMF.settings import MEDIA_ROOT
import os


# Create your views here.
@csrf_exempt
@require_http_methods(['GET', 'POST'])
def rsas_upload(request):
    """绿盟漏扫结果上传"""
    if request.method == 'POST':
        data = request.content_type
        print(request.POST)
        print(request.FILES)
        print(data)
        report = request.FILES.get('file', None)
        file_name = report.name
        with open(MEDIA_ROOT, 'wb+') as dst:  # 打开特定的文件进行二进制的写操作
            for chunk in report.chunks():  # 分块写入文件
                dst.write(chunk)
        return JsonResponse({'success': 'hello, this is POST method',
                             'data': file_name,
                             })

    return JsonResponse({'error': 'not allow'})
