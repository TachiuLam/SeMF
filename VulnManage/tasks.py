# coding:utf-8
'''
Created on 2017/11/3

@author: gy
'''
from django.shortcuts import  get_object_or_404
from xml.dom.minidom import parse
from VulnManage.models import Vulnerability, Vulnerability_scan
from celery import shared_task
from NoticeManage.views import notice_add
from django.contrib.auth.models import User
from SeMF.redis import Cache
from API.Functions import dinktalk
from API.Functions import dingtalk_msg


@shared_task
def parse_cnvdxml(filepath):
    DOMTree = parse(filepath)
    collection = DOMTree.documentElement
    if collection.hasAttribute('shelf'):
        print('ok: %s' % collection.getAttribute('shelf'))
    Vulnerabities_in = collection.getElementsByTagName('vulnerability')
    for vulnerabit in Vulnerabities_in:
        try:
            number = vulnerabit.getElementsByTagName('number')[0]
            # print('number: %s' % number.childNodes[0].data)
            cveNumber = vulnerabit.getElementsByTagName('cveNumber')[0]
            # print('cveNumber: %s' % cveNumber.childNodes[0].data)
            title = vulnerabit.getElementsByTagName('title')[0]
            # print('title: %s' % title.childNodes[0].data)
            serverity = vulnerabit.getElementsByTagName('serverity')[0]
            # print('serverity: %s' % serverity.childNodes[0].data)
            product = vulnerabit.getElementsByTagName('product')[0]
            # print('product: %s' % product.childNodes[0].data)
            submitTime = vulnerabit.getElementsByTagName('submitTime')[0]
            # print('submitTime: %s' % submitTime.childNodes[0].data)
            referenceLink = vulnerabit.getElementsByTagName('referenceLink')[0]
            # print('referenceLink: %s' % referenceLink.childNodes[0].data)
            description = vulnerabit.getElementsByTagName('description')[0]
            # print('description: %s' % description.childNodes[0].data)
            formalWay = vulnerabit.getElementsByTagName('formalWay')[0]
            # print('formalWay: %s' % formalWay.childNodes[0].data)
            patchName = vulnerabit.getElementsByTagName('patchName')[0]
            # print('patchName: %s' % patchName.childNodes[0].data)
            # patchDescription = vulnerabit.getElementsByTagName('patchDescription')[0]
            # print('patchDescription: %s' % patchDescription.childNodes[0].data)
            cve_id = cveNumber.childNodes[0].data
            cnvd_id = number.childNodes[0].data
            cve_name = title.childNodes[0].data
            leave = serverity.childNodes[0].data
            scopen = product.childNodes[0].data
            introduce = description.childNodes[0].data + '\n' + referenceLink.childNodes[0].data
            fix = formalWay.childNodes[0].data + '\n' + patchName.childNodes[0].data
            update_data = submitTime.childNodes[0].data

            vuln_get = Vulnerability.objects.get_or_create(
                cve_id=cve_id,
                cnvd_id=cnvd_id,
                cve_name=cve_name,
            )
            vuln = vuln_get[0]
            vuln.leave = leave
            vuln.scopen = scopen
            vuln.introduce = introduce
            vuln.fix = fix
            vuln.update_data = update_data
            vuln.save()
        except Exception as e:
            print(e)
            pass
    data_manage = {
        'notice_title': '漏洞库更新通知',
        'notice_body': '漏洞文件已更新',
        'notice_url': '/vuln/cnvd/',
        'notice_type': 'notice',
    }
    user_manage_list = User.objects.filter(is_superuser=True)
    for user_manage in user_manage_list:
        notice_add(user_manage, data_manage)


def vulnlist_save_status(v_id, fix_status):
    vuln_id_list = eval(Cache.get_value(v_id))
    for each in vuln_id_list:
        vuln = Vulnerability_scan.objects.filter(vuln_id=each).first()
        if vuln.fix_status == '5':  # 修改为已派发时，重置漏洞受理人
            vuln.process_user = None
        vuln.fix_status = fix_status
        vuln.save()
    return True


def vulnlist_assign(v_id, user, username_list):
    vuln_id_list = eval(Cache.get_value(v_id))
    token = dinktalk.DinkTalk.get_access_token()

    msg = dingtalk_msg.DingTalkMsg.assign_msg(vuln_id_list)
    error = dinktalk.DinkTalk.corp_conversation(user=user,
                                                vuln=vuln_id_list,
                                                access_token=token,
                                                user_name_list=username_list,
                                                msg=msg)

    if error.get('errcode') == 0 and username_list:  # 派发成功时，保存派发人员列表：str
        for vuln_id in vuln_id_list:
            username = []
            vuln = get_object_or_404(Vulnerability_scan, vuln_id=vuln_id)
            if not vuln.assign_user:  # 未派发过的漏洞
                vuln.assign_user = str(username_list)
            else:  # 已派发过的漏洞，派发用户列表进行追加
                u = eval(vuln.assign_user)
                username.extend(username_list)
                username.extend(u)
                # 列表去重
                username = list(set(username))
                vuln.assign_user = str(username)
                vuln.save()
    return error
