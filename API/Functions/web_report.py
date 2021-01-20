#!/usr/bin/python3
# -*- coding : utf-8 -*-
# @Author    : Tachiu Lam
# @Mail      : lintechao@yingzi.com
# @Datetime  : 2021/1/18 11:41
# @Software  : PyCharm
from AssetManage.models import Asset
from .vulnerability import VulnerabilityManage
import pandas as pd
import time
import re


class WebReport:
    """渗透测试报告处理类"""

    @staticmethod
    def none_value_trans(string):
        result = '' if str(string) == 'nan' else string
        return result

    @staticmethod
    def vuln_fix_status(fix_status):
        fix_status_info = {
            '已忽略': "0",
            '已修复': "1",
            '待修复': "2",
            '漏洞重现': "3",
            '修复中': "4",
            '已派发': "5",
            '修复完成': "6",
        }
        fix_status = fix_status_info.get(fix_status) if fix_status_info.get(fix_status) else "2"
        return fix_status

    @staticmethod
    def vuln_security(level):
        level_info = {"信息": "0", "低危": "1", "中危": "2", "高危": "3", "紧急": "4"}
        level = level_info.get(level) if level_info.get(level) else "0"
        return level

    @classmethod
    def vlun_add_or_update(cls, num_id, vuln_info):
        """
        关联漏洞信息，漏洞信息只新增和更新，不自动删除
        :param num_id: 根据资产id获取相应字段进行关联
        :param vuln_info: 单个漏洞dict格式化数据
        :return: {'result': '执行结果'}
        """
        v_num_id = VulnerabilityManage.get_vuln_id() + 1  # 获取漏洞表id
        v_num_id_2 = VulnerabilityManage.get_vuln_id(v_type='2') + 1  # 获取漏洞库表id

        exits = VulnerabilityManage.status(num_id=num_id, name=vuln_info.get("name"), v_num_id=v_num_id)
        vuln_info['asset'] = exits['asset']  # 先进行漏洞和资产绑定，避免删除其他资产漏洞
        if exits.get('exits') is True:
            res = VulnerabilityManage.update_or_create(vuln_info, exits=True).get('result')
        else:
            vuln_info['fix_status'] = exits['fix_status']
            vuln_info['v_id'] = exits['v_id']
            vuln_info['v_type'] = exits['v_type']
            res = VulnerabilityManage.update_or_create(vuln_info, exits=False).get('result')
            v_num_id += 1  # 新建查询漏洞，漏洞id都需要递增
        # 导入漏洞库
        exits2 = VulnerabilityManage.status(name=vuln_info['name'], v_num_id=v_num_id_2, v_type='2')
        if exits2.get('exits') is True:
            res2 = VulnerabilityManage.update_or_create(vuln_info, exits=True, v_type='2').get('result')
        else:
            vuln_info['v_id'] = exits2['v_id']
            res2 = VulnerabilityManage.update_or_create(vuln_info, exits=False, v_type='2').get('result')
            v_num_id_2 += 1  # 新建查询漏洞，漏洞id都需要递增
        return {'result': [res, res2]}

    @staticmethod
    def asset_type_check(asset):
        """检测资产类型"""
        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                    asset):
            asset_type_id = 4  # 服务器22
        else:
            asset_type_id = 14  # web应用31
        return asset_type_id

    @classmethod
    def asset_add_or_update(cls, asset):
        """
        资产添加或导入
        :param asset: 资产key，此处为url
        :param area: 所属项目
        :return:
        """
        try:
            num_id = Asset.objects.latest('id').id
        except Exception as error:
            print(error)
            num_id = 0

        asset_name = asset_key = asset
        asset_type_id = WebReport.asset_type_check(asset)
        exits = Asset.objects.filter(asset_key=asset_key).first()  # 查看唯一值asset_key是否存在
        if not exits:
            try:
                num_id += 1
                asset_id = '02' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(num_id)
                asset_create = Asset.objects.get_or_create(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    asset_type_id=asset_type_id,
                    asset_key=asset_key,
                    asset_area_id=13,  # 默认归类到安全组项目
                )
                # asset_create : (<Asset: asset_key>, True)
                if asset_create[1]:
                    asset_create[0].save()
            except Exception as error:
                print(error)
                pass
                return {'ip': None, 'id': None}
        else:  # IP已存在的情况,需要查找到资产对应的id，并更新资产类型
            num_id = Asset.objects.get(asset_key=asset_key).id
            Asset.objects.filter(asset_key=asset_key).update(asset_type_id=asset_type_id)
        return num_id

    @classmethod
    def web_report_type_v1(cls, filename):
        """
        渗透测试报告类型=1的处理
        :param filename: 漏洞报告的绝对路径+文件名
        :return:
        """
        # 导入web资产
        web_info = pd.read_excel(filename, sheet_name=0).to_dict()
        for each in web_info:
            print(each, web_info.get(each))
        asset_info = web_info.get("Unnamed: 2")
        for n, key in enumerate(asset_info):
            if n > 1:
                # 同一行漏洞一致，只需初始化依次
                vuln_info = {"name": WebReport.none_value_trans(web_info.get("漏洞统计").get(n)),
                             "level": WebReport.vuln_security(web_info.get("Unnamed: 1").get(n)),
                             "project": WebReport.none_value_trans(web_info.get("Unnamed: 3").get(n)),
                             "owner": WebReport.none_value_trans(web_info.get("Unnamed: 4").get(n)),
                             "fix_status": WebReport.vuln_fix_status(web_info.get("Unnamed: 5").get(n)),
                             "note": WebReport.none_value_trans(web_info.get("Unnamed: 6").get(n))}
                print(vuln_info)
                for asset in asset_info.get(key).split("\n"):
                    num_id = WebReport.asset_add_or_update(asset)
                    # 根据资产导入漏洞
                    vuln_result = WebReport.vlun_add_or_update(num_id, vuln_info)
                    print(vuln_result)
        return True

    @classmethod
    def main(cls, filename, report_type="1"):
        if report_type == "1":
            WebReport.web_report_type_v1(filename)

        return True

