# -*- coding: utf-8 -*-
# tachiu lam
# techaolin@gmail.com
# 2020/6/6 10:28 下午
# PyCharm
from AssetManage.models import Asset, Port_Info, AssetType
from VulnManage.models import Vulnerability_scan
from SeMF.settings import MEDIA_API
import pandas as pd
import os
import time


class RSAS:
    """处理绿盟极光扫描器报告/.xls格式"""

    @staticmethod
    def end_with(path=None):
        """
        获得路径下所有.xls文件的绝对路径
        :param path: 传入各个IP的xls报告所在路径
        :return: 返回文件名绝对路径列表或None
        """
        try:
            all_files = os.listdir(path)
            file_list = []
            for each_file in all_files:
                if each_file.endswith('.xls') and each_file != 'index.xls':
                    file_list.append(os.path.join(path, each_file))
            return file_list
        except FileNotFoundError:
            return None

    @classmethod
    def vuln_severity(cls, severity):
        """
        将rsas漏洞等级转义为数据库对应字段[信息、低危、中危、高危、紧急]
        :param severity:  rsas漏洞等级
        :return: 低危 | 中危 ...
        """
        if severity == '[低]':
            return '1'
        elif severity == '[中]':
            return '2'
        elif severity == '[高]':
            return '3'
        else:
            return '0'

    @staticmethod
    def port_update(num_id, filename):
        """
        根据asset_key即IP刷新该主机开放端口:删除旧端口、添加新端口
        :param num_id: 资产表id字段
        :param filename: 单个ip.xls的绝对路径+文件名
        :return: {'result': '处理结果'}
        """
        Port_Info.objects.filter(asset_id=num_id).delete()  # 删除已有端口

        other_info = pd.read_excel(filename, sheet_name=2).to_dict()
        # dict_keys(['操作系统类型', 'Unnamed: 1', 'Unnamed: 2', 'Unnamed: 3', 'Unnamed: 4'])
        # print(other_info.keys())
        # print(other_info.get('操作系统类型').keys())
        if other_info.get('操作系统类型'):
            k = [k for (k, v) in other_info.get('操作系统类型').items() if v == '端口信息']  # ep: k = [7]
            if k:
                k = int(k[0])  # 确定端口信息在第k行，根据csv报告，需要提取的单元格从(1,9)-(4,9,)四格
                while k:
                    # 参考Asset.models.Port_Info
                    port = other_info.get('Unnamed: 1').get(k + 2)
                    port_product = other_info.get('Unnamed: 3').get(k + 2)
                    port_info = other_info.get('Unnamed: 4').get(k + 2)
                    if str(port) == 'nan' or port is None:  #
                        break
                    # 写入新端口
                    Port_Info.objects.get_or_create(
                        port=port,
                        product=port_product,
                        port_info=port_info,
                        asset_id=num_id,
                    )
                    k += 1
            return {'result': '端口更新成功'}
        return {'result': '无端口信息'}

    @classmethod
    def vlun_add_or_update(cls, num_id, filename):
        """
        关联漏洞信息，漏洞信息只新增不自动删除
        :param num_id: 根据资产id获取相应字段进行关联
        :param filename:  单个ip.xls的绝对路径+文件名
        :return: {'result': '执行结果'}
        """
        # vuln_data.keys():['端口', '协议', '服务', '漏洞名称', '漏洞风险值', '风险等级', '服务分类','应用分类',
        #                   '系统分类', '威胁分类', '时间分类', 'CVE年份分类', '发现日期', 'CVE编号', 'CNNVD编号',
        #                   'CNCVE编号', 'CNVD编号', '详细描述', '解决办法', '返回信息']
        # 获得资产字段，进行漏洞信息关联
        asset = Asset.objects.get(id=num_id)
        asset_type_id = asset.asset_type_id
        asset_type_name = asset.asset_type.name

        # Vulnerability_scan.objects.filter(vuln_asset_id=num_id).delete()  # 删除已有漏洞
        v_info = pd.read_excel(filename, sheet_name=1).to_dict()
        if v_info.get('漏洞名称'):
            try:
                v_num_id = Vulnerability_scan.objects.latest('id').id + 1
            except Exception as error:
                print(error)
                v_num_id = 0


            rows = len(v_info.get('漏洞名称'))
            for row in range(rows):
                # rsas相同端口和协议是合并行保存的，需要处理
                if str(v_info.get('端口').get(row)) == 'nan':
                    v_info['端口'][row] = str(v_info.get('端口').get(row - 1)).replace('.0', '')
                v_port = str(v_info.get('端口').get(row)).replace('.0', '')
                v_level = cls.vuln_severity(v_info.get('风险等级').get(row))
                v_name = v_info.get('漏洞名称').get(row)
                v_introduce = v_info.get('详细描述').get(row)
                v_fix = v_info.get('解决办法').get(row)
                v_cve = v_info.get('CVE编号').get(row)

                v_type = asset_type_name  # 漏洞类型，关联到资产类型
                v_id = str(asset_type_id) + time.strftime('%Y%m%d', time.localtime(time.time())) + str(v_num_id)
                # print(v_port, v_level, v_name, v_introduce, v_fix, v_type, v_id, v_cve)

                res = Vulnerability_scan.objects.get_or_create(
                    vuln_name=v_name,
                    cve_name=v_cve,
                    vuln_type=v_type,
                    leave=v_level,
                    introduce=v_introduce,
                    vuln_info=v_introduce,
                    scopen=v_port,
                    fix=v_fix,
                    vuln_asset=asset,
                )
                vuln = res[0]
                # 漏洞修复状态初始化
                if vuln.vuln_id == v_id:         # 漏洞已存在
                    if vuln.fix_status == '1':   # 若状态已修复，置为漏洞复现；其余情况维持漏洞状态
                        vuln.fix_status = '3'
                else:
                    vuln.vuln_id = v_id        # 漏洞未存在
                    if v_level == '0':          # 威胁等级为 信息
                        vuln.fix_status = '0'    # 状态修改为 已忽略
                    vuln.fix_status = '2'

                v_num_id += 1  # 新建查询漏洞，漏洞id都需要递增
                vuln.save()

            return {'result': '漏洞导入成功'}
        return {'result': '无漏洞信息'}

    @classmethod
    def report_main(cls, filename):
        # sheet json数据格式为去（前行后列）：{(0,0):{(0,1),(0,2)...},(1,0):{(1,1),(1,2)..,}
        # 要取坐标(1,2)单元格的值，则data.get('(1,0)').get(1)

        # 导入IP资产
        host_info = pd.read_excel(filename, sheet_name=0).to_dict()
        try:
            num_id = Asset.objects.latest('id').id
        except Exception as error:
            print(error)
            num_id = 0

        asset_name = asset_key = asset_description = host_info.get('Unnamed: 1').get(
            1)  # 获取ip地址,Unnamed: 1所在列的第二个键（不包含首行）
        asset_type_id = 5  # 服务器
        # asset_type = AssetType.objects.get(id=asset_type_id).name   # 根据asset_type_id获取对应的资产类型名称：如，服务器
        # print('类型名字：' + asset_type)
        asset_key = Asset.objects.filter(asset_key=asset_key).first()  # 查看唯一值asset_key是否存在
        if not asset_key:
            try:
                num_id += 1  # num_id还需要用于关联端口,只有IP未创建时才+1，避免影响端口更新，此时导入的IP资产对应最新的id
                asset_id = '01' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(num_id)
                asset_create = Asset.objects.get_or_create(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    asset_type_id=asset_type_id,
                    asset_key=asset_key,
                    # asset_description=asset_description,
                )
                # asset_create : (<Asset: asset_key>, True)
                if asset_create[1]:
                    asset_create[0].save()
            except Exception as error:
                print(error)
                pass
            return {'ip': None, 'id': None}
        else:  # IP已存在的情况,需要查找到资产对应的id
            num_id = Asset.objects.get(asset_key=asset_key).id
        # 更新端口
        port_result = cls.port_update(num_id, filename)
        # 导入漏洞，后续逻辑需要细化
        vuln_result = cls.vlun_add_or_update(num_id, filename)
        return {'ip': asset_key, 'port': port_result, 'vulnerability': vuln_result}


if __name__ == '__main__':
    file1 = r'C:\Users\lintechao\Downloads\711_2020扫描1.0.2_2020_05_09_xls'
    fl = RSAS.end_with(file1)
    for f in fl:
        RSAS.report_main(f)
        RSAS.port_update('ip', f)
