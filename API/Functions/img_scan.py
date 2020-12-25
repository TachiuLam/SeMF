#!/usr/bin/python3
# -*- coding : utf-8 -*-
# @Author    : Tachiu Lam
# @Mail      : lintechao@yingzi.com
# @Datetime  : 2020/12/10 17:31
# @Software  : PyCharm

import time
import json
import requests
from AssetManage.models import Asset
from API.Functions.vulnerability import VulnerabilityManage


class Img_Scan:
    """镜像漏洞获取、保存类"""

    @classmethod
    def transform_severity_to_level(cls, severity):
        """将扫描报告中的severity转换为相应level"""
        level_table = {
            "Unknown": 0, "Negligible": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4
        }
        level = level_table.get(severity) if level_table.get(severity) else 0
        return level

    @classmethod
    def generate_api(cls, content):
        """构造获取harbor对应镜像漏洞的api"""
        resources = content.get('event_data').get('resources')[0]
        repository = content.get('event_data').get('repository')

        img_name = repository.get('name')
        namespace = repository.get('namespace')
        sha256 = resources.get('digest')
        resource_url = resources.get('resource_url').split('/')[0]
        scan_status = resources.get('scan_overview').get(
            'application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0').get('scan_status')
        scanner = resources.get('scan_overview').get(
            'application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0').get(
            'scanner').get('name')

        api_url = 'http://' + resource_url + '/api/v2.0/projects/' + namespace + '/repositories/' + img_name + '/artifacts/' + sha256 + '/additions/vulnerabilities'
        return {'api_url': api_url, 'sha256': sha256, 'img_name': img_name}

    @classmethod
    def create_or_update_vulnerability(cls, num_id, vulnerability):
        """关联漏洞信息，漏洞信息只新增和更新，不自动删除"""
        for each_v in vulnerability:
            v = {}
            v['cve'] = each_v.get('id')
            v['name'] = each_v.get('package') + ' ' + each_v.get('id')  # 库名+ cve名称作为漏洞名字
            v['fix'] = each_v.get('fix_version')
            v['introduce'] = each_v.get('description')
            v['port'] = each_v.get('version')  # 影响版本，为适应函数，命名为port
            v['introduce'] = v['vuln_info'] = each_v.get('links')[0]
            v['level'] = cls.transform_severity_to_level(each_v.get('severity'))

            v_num_id = VulnerabilityManage.get_vuln_id() + 1  # 获取漏洞表id

            exits = VulnerabilityManage.status(num_id=num_id, name=v['name'], v_num_id=v_num_id)

            v['asset'] = exits['asset']  # 先进行漏洞和资产绑定，避免删除其他资产漏洞
            if exits.get('exits') is True:
                v['fix_status'] = exits['fix_status']  # 继承漏洞状态
                VulnerabilityManage.update_or_create(v, exits=True).get('result')
            else:
                v['fix_status'] = exits['fix_status']
                v['v_id'] = exits['v_id']
                v['v_type'] = exits['v_type']
                VulnerabilityManage.update_or_create(v, exits=False).get('result')
                v_num_id += 1  # 新建查询漏洞，漏洞id都需要递增

        return {'result': '漏洞导入成功'}

    @classmethod
    def scan_deal(cls, api_url, sha256, img_name):
        """获取harbor漏洞接口的数据，新建or更新资产，更新漏洞信息"""
        content = requests.get(api_url, verify=False).content   # 自签证书需要取消证书校验
        with open('./log.txt', 'a') as f:
            f.write(content)
        content = json.loads(content)
        # 判断数据是否存在
        if content.get('application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0'):
            data = content.get('application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0')
            exits = Asset.objects.filter(asset_key=sha256).first()  # 查看唯一值asset_key是否存在
            with open('./log.txt', 'a') as f:
                f.write('44')
            if not exits:
                num_id = Asset.objects.latest('id').id
                num_id += 1  #
                asset_id = '03' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(num_id)  # 镜像ID分类03
                # 资产创建或更新
                asset_create = Asset.objects.get_or_create(
                    asset_id=asset_id,
                    asset_name=img_name,
                    asset_type_id=37,  # 镜像资产分类
                    asset_key=sha256,  # 镜像哈希为唯一ID
                    asset_score=data.get('severity'),
                    asset_area_id=13,  # 默认归类到安全组项目
                    # asset_description=asset_description,
                )
                # asset_create : (<Asset: asset_key>, True)
                if asset_create[1]:
                    asset_create[0].save()
            else:  # 镜像已存在的情况,需要查找到资产对应的id，并更新资产类型
                num_id = Asset.objects.get(asset_key=sha256).id
                Asset.objects.filter(asset_key=sha256).update(asset_type_id=37)

            # 漏洞更新
            vuln_result = cls.create_or_update_vulnerability(num_id, data.get("vulnerabilities"))
            return {'img': sha256, 'vulnerability': vuln_result}
        return {'msg': False}

    @classmethod
    def main(cls, content):
        api_info = cls.generate_api(content)
        api_url = api_info.get("api_url")
        sha256 = api_info.get("sha256")
        img_name = api_info.get("img_name")

        result = cls.scan_deal(api_url, sha256, img_name)
        return result