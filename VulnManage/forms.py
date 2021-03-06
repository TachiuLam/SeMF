# coding:utf-8
'''
Created on 2018年5月21日

@author: yuguanc
'''
from . import models
from django.forms import ModelForm, widgets


class Cnvd_file_form(ModelForm):
    class Meta:
        model = models.Cnvdfiles
        fields = ['file']
        widgets = {
            'file': widgets.FileInput(),
        }


class Vuln_file_form(ModelForm):
    class Meta:
        model = models.Vulnfiles
        fields = ['file']
        widgets = {
            'file': widgets.FileInput(),
        }


class Advance_vulns_form(ModelForm):
    class Meta:
        model = models.Advance_vulns
        fields = ['type', 'vuln_name', 'leave', 'fix']
        widgets = {
            'type': widgets.Select(attrs={'class': 'form-control', 'placeholder': '扫描器关联'}),
            'vuln_name': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '漏洞名称'}),
            'leave': widgets.Select(attrs={'class': 'form-control', 'placeholder': '危险等级'}),
            'fix': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '修复方案', 'style': 'height:100px'}),
        }


class Vuln_edit_form(ModelForm):
    class Meta:
        model = models.Vulnerability_scan
        fields = ['vuln_name', 'cve_name','project', 'leave', 'owner',
                  'scopen', 'introduce', 'vuln_info', 'fix', 'note']
        widgets = {
            'vuln_name': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '漏洞名称'}),
            'cve_name': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': 'cve编号'}),
            'project': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '所属项目'}),
            'owner': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '责任人'}),
            'leave': widgets.Select(attrs={'class': 'form-control', 'placeholder': '危险等级'}),
            'scopen': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '影响范围'}),
            'introduce': widgets.Textarea(
                attrs={'class': 'form-control', 'placeholder': '漏洞介绍', 'style': 'height:100px'}),
            'vuln_info': widgets.Textarea(
                attrs={'class': 'form-control', 'placeholder': '漏洞验证', 'style': 'height:100px'}),
            'fix': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '修复方案', 'style': 'height:100px'}),
            'note': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '备注'}),
        }


class Vuln_action_form(ModelForm):
    class Meta:
        model = models.Vulnerability_scan
        fields = ['fix_status', 'fix_action']
        widgets = {
            'fix_status': widgets.Select(attrs={'class': 'form-control'}),
            'fix_action': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '处理记录，如忽略，请说明原因'}),
        }


class Cnvd_vuln_form(ModelForm):
    class Meta:
        model = models.Vulnerability
        fields = ['vuln_name', 'cve_name', 'leave', 'introduce', 'fix', 'note']
        widgets = {
            'vuln_name': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '漏洞名称'}),
            'cve_name': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': 'cve编号'}),
            'leave': widgets.Select(attrs={'class': 'form-control', 'placeholder': '危险等级'}),
            'introduce': widgets.Textarea(
                attrs={'class': 'form-control', 'placeholder': '漏洞介绍', 'style': 'height:250px'}),
            'fix': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '修复方案', 'style': 'height:250px'}),
            'note': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '其他', 'style': 'height:250px'}),
        }


class Vulnlist_action_form(ModelForm):
    class Meta:
        model = models.VulnlistFix
        fields = ['fix_status', 'fix_action']
        widgets = {
            'fix_status': widgets.Select(attrs={'class': 'form-control'}),
            'fix_action': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '处理记录，如忽略，请说明原因'}),
        }


class Vulnlist_action_form2(ModelForm):
    class Meta:
        model = models.VulnlistFix2
        fields = ['fix_status', 'fix_action']
        widgets = {
            'fix_status': widgets.Select(attrs={'class': 'form-control'}),
            'fix_action': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '处理记录，如忽略，请说明原因'}),
        }


class Vulnlist_assign(ModelForm):
    class Meta:
        model = models.VulnlistAssign
        fields = ['assign_user', 'assign_notes']
        widgets = {
            'assign_user': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '分配人员'}),
            'assign_notes': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '漏洞派发备注'}),
        }
