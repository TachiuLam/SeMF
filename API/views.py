from django.shortcuts import render
from django.http import JsonResponse


# Create your views here.


def rsas_upload(request):
    """绿盟漏扫结果上传"""
    if request.method == 'POST':
        return JsonResponse({'Hello': 'hello, this is POST method'})
    if request.method == 'GET':
        return JsonResponse({'Hello': 'hello, this is GET method'})
    # else:
    #     return JsonResponse({'error': 'method not allow'})
