# coding:utf-8

# Create your views here.
from django.shortcuts import render, HttpResponseRedirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
import django.utils.timezone as timezone
from django.contrib import auth
import datetime
import json
from SeMFSetting.Functions.checkpsd import checkpsd
from . import forms, models
import hashlib
from django.contrib.auth.hashers import make_password
from SeMFSetting.views import paging, strtopsd
from SeMFSetting.Functions import mails
from ArticleManage.models import Article
from AssetManage.models import Asset
from VulnManage.models import Vulnerability, Vulnerability_scan
from .service.init_permission import init_permission
from django.utils.html import escape
from RBAC.service.ldap_auth import ldap_auth, generate_password
from RBAC.service.user_process import get_user_area
from API.Functions.save_img import save_img
from SeMF.redis import Cache
from SeMF.settings import STATICFILES_DIRS, STATIC_URL

REAUEST_STATUS = {
    '0': '待审批',
    '1': '审批通过',
    '2': '审批拒绝',
}


@login_required
def main(request):
    article = Article.objects.filter(article_status='1').last()
    article_list = Article.objects.filter(article_status='1').order_by('-article_updatetime')[:15]

    user_count = User.objects.all().count()
    article_count = Article.objects.filter(article_status='1').count()
    asset_count = Asset.objects.all().count()
    cnvdvuln_count = Vulnerability.objects.all().count()
    vuln_count = Vulnerability_scan.objects.all().count()
    vuln_fix_count = Vulnerability_scan.objects.exclude(fix_status__in=[0, 1]).count()

    return render(request, 'RBAC/main.html', {
        'article': article,
        'article_list': article_list,
        'user_count': user_count,
        'article_count': article_count,
        'asset_count': asset_count,
        'cnvdvuln_count': cnvdvuln_count,
        'vuln_count': vuln_count,
        'vuln_fix_count': vuln_fix_count
    })


@login_required
def dashboard(request):
    context = {}
    user = request.user
    # 钉钉头像获取，使用redis缓存头像保存路径
    img_url = Cache.get_value(key=(str(user)+'_avatar'))
    ding_user = Cache.get_value(key=user)
    if not ding_user:       # 不存在的钉钉用户，返回默认头像
        context['avatar'] = STATIC_URL + "images/default_avatar.png"
    elif img_url:       # 如果缓存内存在用户头像
        context['avatar'] = img_url
    else:       # 从钉钉静态文件地址获取，保存头像，缓存头像本地路径，默认一周，后期增加定时更新头像缓存任务
        file_path = STATICFILES_DIRS[0] + '/images/'
        file_name = ding_user.get('name') + '_avatar.png'
        img_url = ding_user.get('avatar')
        # 保存钉钉头像
        save_img(img_url, file_name, file_path)
        # 缓存
        Cache.set_value(value=(STATIC_URL+'images/'+file_name), key=str(user)+'_avatar', key_time_id=2)
        context['avatar'] = img_url
    return render(request, 'Dashboard.html', context)


@csrf_protect
def regist(request, argu):
    error = ''
    if argu == 'regist':
        if request.method == 'POST':
            form = forms.UserRequestForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data['email']
                user_get = User.objects.filter(username=email)
                if user_get:
                    error = '用户已存在'
                else:
                    userregist_get = models.UserRequest.objects.filter(email=email)
                    if userregist_get.count() > 2:
                        error = '用户已多次添加'
                    else:
                        area = form.cleaned_data['area']
                        request_type = form.cleaned_data['request_type']
                        urlarg = strtopsd(email)
                        models.UserRequest.objects.get_or_create(
                            email=email,
                            urlarg=urlarg,
                            area=area,
                            request_type=request_type,
                        )
                        # res = mails.sendregistmail(email, urlarg)
                        error = '申请成功，审批通过后会向您发送邮箱'
            else:
                error = '请检查输入'
        else:
            form = forms.UserRequestForm()
        return render(request, 'RBAC/registrequest.html', {'form': form, 'error': error})
    else:
        regist_get = get_object_or_404(models.UserRequest, urlarg=argu, is_use=False)
        if request.method == 'POST':
            form = forms.Account_Reset_Form(request.POST)
            if form.is_valid():
                email = form.cleaned_data['email']
                firstname = form.cleaned_data['firstname']
                lastname = form.cleaned_data['lastname']
                password = form.cleaned_data['password']
                repassword = form.cleaned_data['repassword']
                username = email.split("@")[0]
                check_res = checkpsd(password)
                if check_res:
                    if regist_get.email == email:
                        if password == repassword:
                            user_create = auth.authenticate(username=username, password=password)
                            if user_create:
                                error = '用户已存在'
                            else:
                                user_create = User.objects.create_user(
                                    first_name=firstname,
                                    last_name=lastname,
                                    username=username,
                                    password=password,
                                    email=email,
                                )
                                user_create.profile.roles.add(regist_get.request_type)
                                user_create.profile.area = regist_get.area
                                user_create.save()
                                regist_get.is_use = True
                                regist_get.save()
                                return HttpResponseRedirect('/view/')
                        else:
                            error = '两次密码不一致'
                    else:
                        error = '密码必须6位以上且包含字母、数字'
                else:
                    error = '恶意注册是不对滴'
            else:
                error = '请检查输入'
        else:
            form = forms.Account_Reset_Form()
        return render(request, 'RBAC/regist.html', {'form': form, 'error': error})


@csrf_protect
def resetpasswd(request, argu='resetpsd'):
    error = ''
    if argu == 'resetpsd':
        if request.method == 'POST':
            form = forms.ResetpsdRequestForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data['email']
                user = get_object_or_404(User, email=email)
                if user:
                    hash_res = hashlib.md5()
                    hash_res.update(make_password(email).encode('utf-8'))
                    urlarg = hash_res.hexdigest()
                    models.UserResetpsd.objects.get_or_create(
                        email=email,
                        urlarg=urlarg
                    )
                    res = mails.sendresetpsdmail(email, urlarg)
                    if res:
                        error = '申请已发送，请检查邮件通知，请注意检查邮箱'
                    else:
                        error = '重置邮件发送失败，请重试'
                else:
                    error = '请检查信息是否正确'
            else:
                error = '请检查输入'
        else:
            form = forms.ResetpsdRequestForm()
        return render(request, 'RBAC/resetpsdquest.html', {'form': form, 'error': error})
    else:
        resetpsd = get_object_or_404(models.UserResetpsd, urlarg=argu)
        if resetpsd:
            email_get = resetpsd.email
            if request.method == 'POST':
                form = forms.ResetpsdForm(request.POST)
                if form.is_valid():
                    email = form.cleaned_data['email']
                    password = form.cleaned_data['password']
                    repassword = form.cleaned_data['repassword']
                    if checkpsd(password):
                        if password == repassword:
                            if email_get == email:
                                user = get_object_or_404(User, email=email)
                                if user:
                                    user.set_password(password)
                                    user.save()
                                    resetpsd.delete()
                                    return HttpResponseRedirect('/view/')

                                else:
                                    error = '用户信息有误'
                            else:
                                error = '用户邮箱不匹配'
                        else:
                            error = '两次密码不一致'
                    else:
                        error = '密码必须6位以上且包含字母、数字'
                else:
                    error = '请检查输入'
            else:
                form = forms.ResetpsdForm()
            return render(request, 'RBAC/resetpsd.html', {'form': form, 'error': error, 'title': '重置'})


@login_required
@csrf_protect
def changeuserinfo(request):
    user = request.user
    if request.method == 'POST':
        form = forms.UserInfoForm(request.POST, instance=user.profile)
        if form.is_valid():
            if 'parent_email' in form.changed_data:
                parent_email = form.cleaned_data['parent_email']
                parent_user = User.objects.filter(email=parent_email).first()
                if parent_user:
                    user.profile.parent = parent_user
                    user.save()
            form.save()
            error = '修改成功'
        else:
            error = '请检查输入'
        return render(request, 'formedit.html', {'form': form, 'post_url': 'changeuserinfo', 'error': error})
    else:
        form = forms.UserInfoForm(instance=user.profile)
    return render(request, 'formedit.html', {'form': form, 'post_url': 'changeuserinfo'})


@login_required
def userinfo(request):
    return render(request, 'RBAC/userinfo.html')


@login_required
@csrf_protect
def changepsd(request):
    if request.method == 'POST':
        form = forms.ChangPasswdForm(request.POST)
        if form.is_valid():
            old_password = form.cleaned_data['old_password']
            new_password = form.cleaned_data['new_password']
            re_new_password = form.cleaned_data['re_new_password']
            username = request.user.username
            if checkpsd(new_password):
                if new_password and new_password == re_new_password:
                    if old_password:
                        user = auth.authenticate(username=username, password=old_password)
                        if user:
                            user.set_password(new_password)
                            user.save()
                            auth.logout(request)
                            error = '修改成功'
                        else:
                            error = '账号信息错误'
                    else:
                        error = '请检查原始密码'
                else:
                    error = '两次密码不一致'
            else:
                error = '密码必须6位以上且包含字母、数字'
        else:
            error = '请检查输入'
        return render(request, 'formedit.html', {'form': form, 'post_url': 'changepsd', 'error': error})
    else:
        form = forms.ChangPasswdForm()
    return render(request, 'formedit.html', {'form': form, 'post_url': 'changepsd'})


@login_required
def logout(request):
    auth.logout(request)
    request.session.clear()
    return HttpResponseRedirect('/view/')


@csrf_protect
def login(request):
    if request.method == 'POST':
        form = forms.SigninForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            # 先进行ldap认证
            ldap_auth_res = ldap_auth(username=username, password=password)
            if ldap_auth_res.get('auth_res'):
                # 判断ldap用户是否已在本地创建
                user_get = User.objects.filter(username=username).first()
                # 若未创建，新建用户，增加本机随机密码
                if not user_get:
                    User.objects.create(username=username, email=ldap_auth_res.get('mail'),
                                        password=generate_password(16))
                    user_get = User.objects.filter(username=username).first()
                else:
                    # 更新密码错误累计次数
                    user_get.profile.error_count = 0
                    user_get.save()
                # 添加此行才可认证
                auth.login(request, user_get)
                # 这里需要加入权限初始化
                init_permission(request, user_get)
                return HttpResponseRedirect('/user/')
            # 本地账号认证
            else:
                user_get = User.objects.filter(username=username).first()
                if user_get:
                    if user_get.profile.lock_time > timezone.now():
                        error = u'账号已锁定,' + str(user_get.profile.lock_time.strftime("%Y-%m-%d %H:%M")) + '后可尝试'
                    else:
                        user = auth.authenticate(username=username, password=password)
                        if user:
                            user.profile.error_count = 0
                            user.save()
                            auth.login(request, user)
                            # 这里需要加入权限初始化
                            init_permission(request, user)
                            return HttpResponseRedirect('/user/')
                        else:
                            user_get.profile.error_count += 1
                            if user_get.profile.error_count >= 5:
                                user_get.profile.error_count = 0
                                user_get.profile.lock_time = timezone.now() + datetime.timedelta(minutes=10)
                            user_get.save()
                            error = '登陆失败,已错误登录' + str(user_get.profile.error_count) + '次,5次后账号锁定',
                else:
                    error = '请检查用户信息'
        else:
            error = u'请检查输入'
        return render(request, 'RBAC/login.html', {'form': form, 'error': error})
    else:
        if request.user.is_authenticated:
            return HttpResponseRedirect('/user/')
        else:
            form = forms.SigninForm()
    return render(request, 'RBAC/login.html', {'form': form})


@login_required
@csrf_protect
def userlist(request):
    user = request.user
    if user.is_superuser or (get_user_area(user).get('is_admin')):
        area = models.Area.objects.filter(parent__isnull=True)
        city = models.Area.objects.filter(parent__isnull=False)
        return render(request, 'RBAC/userlist.html', {'area': area, 'city': city})
    else:
        error = '权限错误'
    return render(request, 'error.html', {'error': error})


@login_required
@csrf_protect
def userlisttable(request):
    user = request.user
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')
    email = request.POST.get('email')
    if not email:
        email = ''

    area = request.POST.get('area')
    if not area:
        area_get = models.Area.objects.filter(parent__isnull=True)
    else:
        area_get = models.Area.objects.filter(id=area)
    is_active = request.POST.get('is_active')
    if not is_active:
        is_active = ['True', 'False']
    else:
        is_active = [is_active]
    if user.is_superuser or (get_user_area(user).get('is_admin')):
        user_list = User.objects.filter(
            email__icontains=email,
            profile__area__in=area_get,
            is_active__in=is_active
        ).order_by('-is_superuser', '-date_joined')
        total = user_list.count()
        user_list = paging(user_list, rows, page)
        data = []
        for user_item in user_list:
            dic = {}
            dic['name'] = user_item.first_name + user_item.last_name
            dic['mail'] = user_item.email
            dic['date'] = user_item.date_joined
            if user_item.profile.area:
                dic['area'] = user_item.profile.area.name
            else:
                dic['area'] = '未知'
            dic['title'] = user_item.profile.title
            if user_item.is_active:
                dic['status'] = '启用'
            else:
                dic['status'] = '禁用'
            dic['lastlogin'] = user_item.last_login
            role = user_item.profile.roles.all()
            roles = []
            for item in role:
                roles.append(item.title)
            dic['role'] = roles
            data.append(dic)
        resultdict['code'] = 0
        resultdict['msg'] = "用户列表"
        resultdict['count'] = total
        resultdict['data'] = data
        return JsonResponse(resultdict)
    else:
        error = '权限错误'
    return render(request, 'error.html', {'error': error})


@login_required
@csrf_protect
def userregistaction(request):
    user = request.user
    if user.is_superuser or (get_user_area(user).get('is_admin')):
        regist_id = request.POST.get('request_id')
        action = request.POST.get('action')
        userregist = get_object_or_404(models.UserRequest, id=regist_id)
        if userregist.is_check:
            error = '请勿重复审批'
        else:
            if action == 'access':
                userregist.is_check = True
                userregist.status = '1'
                res = mails.sendregistmail(userregist.email, userregist.urlarg)
                if res:
                    error = '添加成功，已向该员工发送邮件'
                else:
                    error = '添加成功，邮件发送失败，请重试'
                userregist.save()
            elif action == 'deny':
                userregist.is_check = True
                userregist.status = '2'
                userregist.is_use = True
                userregist.save()
                error = '已审批'
            else:
                error = '未指定操作'
    else:
        error = '权限错误'
    return JsonResponse({'error': error})


@login_required
def userregistlist(request):
    user = request.user
    if user.is_superuser or (get_user_area(user).get('is_admin')):
        area = models.Area.objects.filter(parent__isnull=True)
        return render(request, 'RBAC/userregistlist.html', {'area': area})
    else:
        error = '权限错误'
    return render(request, 'error.html', {'error': error})


@login_required
@csrf_protect
def userregisttable(request):
    user = request.user
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    email = request.POST.get('email')
    if not email:
        email = ''
    status = request.POST.get('status')
    if not status:
        status = ''
    is_use = request.POST.get('is_use')
    if not is_use:
        is_use = ['True', 'False']
    else:
        is_use = [is_use]
    is_check = request.POST.get('is_check')
    if not is_check:
        is_check = ['True', 'False']
    else:
        is_check = [is_check]

    if user.is_superuser or (get_user_area(user).get('is_admin')):
        userrequest_list = models.UserRequest.objects.filter(email__icontains=email, status__icontains=status,
                                                             is_use__in=is_use, is_check__in=is_check).order_by(
            'is_check', 'is_use', '-updatetime')
        total = userrequest_list.count()
        userrequest_list = paging(userrequest_list, rows, page)
        data = []
        for userrequest in userrequest_list:
            dic = {}
            dic['request_id'] = escape(userrequest.id)
            dic['email'] = escape(userrequest.email)
            if userrequest.is_check:
                dic['is_check'] = escape('已审批')
                dic['starttime'] = escape(userrequest.starttime)
                if userrequest.action_user:
                    dic['action_user'] = escape(userrequest.action_user.username)
                dic['updatetime'] = escape(userrequest.updatetime)
            else:
                dic['is_check'] = escape('待审批')
            if userrequest.is_use:
                dic['is_use'] = escape('已使用')
            else:
                dic['is_use'] = escape('待使用')
            dic['request_type'] = escape(userrequest.request_type.title)
            dic['status'] = escape(REAUEST_STATUS[userrequest.status])
            data.append(dic)
        resultdict['code'] = 0
        resultdict['msg'] = "用户申请列表"
        resultdict['count'] = total
        resultdict['data'] = data
        return JsonResponse(resultdict)
    else:
        error = '权限错误'
    return render(request, 'error.html', {'error': error})


@login_required
@csrf_protect
def user_add(request):
    user = request.user
    error = ''
    if user.is_superuser or (get_user_area(user).get('is_admin')):
        if request.method == 'POST':
            form = forms.UserRequestForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data['email']
                user_get = User.objects.filter(username=email)
                if user_get:
                    error = '用户已存在'
                else:
                    userregist_get = models.UserRequest.objects.filter(email=email)
                    if userregist_get.count() > 2:
                        error = '用户已多次添加'
                    else:
                        area = form.cleaned_data['area']
                        request_type = form.cleaned_data['request_type']
                        urlarg = strtopsd(email)
                        models.UserRequest.objects.get_or_create(
                            email=email,
                            urlarg=urlarg,
                            area=area,
                            request_type=request_type,
                            is_check=True,
                            status='1',
                            action_user=user,
                        )
                        res = mails.sendregistmail(email, urlarg)
                        if res:
                            error = '添加成功，已向该员工发送邮件'
                        else:
                            error = '添加成功，邮件发送失败，请重试'
            else:
                error = '请检查输入'
        else:
            form = forms.UserRequestForm()
    else:
        error = '请检查权限是否正确'
    return render(request, 'formedit.html', {'form': form, 'post_url': 'useradd', 'error': error})


@login_required
@csrf_protect
def user_request_cancle(request):
    user = request.user
    if user.is_superuser or (get_user_area(user).get('is_admin')):
        regist_id_list = request.POST.get('regist_id_list')
        regist_id_list = json.loads(regist_id_list)
        action = request.POST.get('action')
        for regist_id in regist_id_list:
            userregist = get_object_or_404(models.UserRequest, id=regist_id)
            userregist.status = '2'
            userregist.is_check = True
            userregist.is_use = True
            userregist.save()
        error = '已禁用'
    else:
        error = '权限错误'
    return JsonResponse({'error': error})


@login_required
@csrf_protect
def user_disactivate(request):
    user = request.user
    if user.is_superuser or (get_user_area(user).get('is_admin')):
        user_list = request.POST.get('user_list')
        user_list = json.loads(user_list)
        action = request.POST.get('action')
        for user_mail in user_list:
            user_get = get_object_or_404(User, email=user_mail)
            if action == 'stop':
                user_get.is_check = True
                user_get.is_active = False
            elif action == 'start':
                user_get.is_active = True
            user_get.save()
        error = '已禁用'
    else:
        error = '权限错误'
    return JsonResponse({'error': error})
