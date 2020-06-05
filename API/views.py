from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required


# Create your views here.

@login_required()
def rsas_upload(request):
    """绿盟漏扫结果上传"""
    if request.method == 'POST':
        return JsonResponse({'Hello': 'hello, this is POST method'})
    if request.method == 'GET':
        return JsonResponse({'Hello': 'hello, this is GET method'})
    # else:
    #     return JsonResponse({'error': 'method not allow'})
