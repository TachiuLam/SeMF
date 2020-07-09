# -*- coding: utf-8 -*-
# tachiu lam
# techaolin@gmail.com
# 2020/6/6 10:28 下午
# PyCharm
from AssetManage.models import Asset, Port_Info
from .vulnerability import Vulnerability
import pandas as pd
import os
import time
import zipfile


class RSAS:
    """处理绿盟极光扫描器报告/.xls格式"""
    @staticmethod
    def report_type(file_name):
        """
        根据上传的报告文件名判断报告类型【服务器/办公设备/容器等】
        :param file_name:
        :return: 漏洞报告类型
        """
        report_type = {'server': 22, 'office': 23, 'docker': 24}
        for key in report_type:
            if key in str(file_name):
                return report_type.get(key)
        # 默认为 server
        return report_type.get('server')

    @classmethod
    def unzip_file(cls, zip_src, dst_dir):
        """
        :param zip_src: 压缩文件的绝对路径
        :param dst_dir: 解压后所在的文件夹
        :return: 返回文件名绝对路径列表或None
        """
        fz = zipfile.ZipFile(str(zip_src), 'r')
        for file in fz.namelist():
            fz.extract(file, dst_dir)
        file_list = cls.end_with(dst_dir)
        return file_list

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
    def vuln_severity(cls, score):
        """
        将rsas漏洞等级风险值为数据库对应字段[信息、低危、中危、高危、紧急]
        :param score:  rsas漏洞风险值
        :return: 低危 | 中危 ...
        """
        score = float(score)
        if score < 2.0:
            return '0'
        elif 2.0 <= score < 4.0:
            return '1'
        elif 4.0 <= score < 7.0:
            return '2'
        elif 7.0 <= score <= 10.0:
            return '3'
        else:
            return '0'

    @classmethod
    def port_update(cls, num_id, filename):
        """
        根据asset_key即IP刷新该主机开放端口:删除旧端口、添加新端口
        :param num_id: 资产表id字段
        :param filename: 单个ip.xls的绝对路径+文件名
        :return: {'result': '处理结果'}
        """
        Port_Info.objects.filter(asset_id=num_id).delete()  # 删除已有端口

        other_info = pd.read_excel(filename, sheet_name=2).to_dict()
        # print(list(other_info.values())[0].items())
        # if other_info.get('操作系统类型'):
        #     k = [k for (k, v) in other_info.get('操作系统类型').items() if v == '端口信息']  # ep: k = [7]
        k = cls.port_line(other_info)
        # 确定端口信息在第k行，根据csv报告，需要提取的单元格从(1,9)-(4,9,)四格
        while k or k == 0:
            # 参考Asset.models.Port_Info
            port = other_info.get('Unnamed: 1').get(k + 2)
            port_product = other_info.get('Unnamed: 3').get(k + 2)
            port_info = other_info.get('Unnamed: 4').get(k + 2)
            if str(port) == 'nan' or port is None:
                return {'result': '端口更新成功'}
            # 写入新端口
            Port_Info.objects.get_or_create(
                port=port,
                product=port_product,
                port_info=port_info,
                asset_id=num_id,
            )
            k += 1

        return {'result': '无端口信息'}

    @staticmethod
    def port_line(other_info):
        if other_info:  # other_info不为空时
            if other_info.get('端口信息'):  # 当"端口信息"在第一行时
                # dict_keys(['端口信息', 'Unnamed: 1', 'Unnamed: 2', 'Unnamed: 3', 'Unnamed: 4'])
                return 0
            else:  # 当"端口信息"不在第一行时
                # dict_keys(['任意列名', 'Unnamed: 1', 'Unnamed: 2', 'Unnamed: 3', 'Unnamed: 4'])
                k = [k for (k, v) in list(other_info.values())[0].items() if v == '端口信息']  # ep: k = [7]
                if k:
                    return int(k[0])
        return None

    @classmethod
    def vlun_add_or_update(cls, num_id, filename):
        """
        关联漏洞信息，漏洞信息只新增和更新，不自动删除
        :param num_id: 根据资产id获取相应字段进行关联
        :param filename:  单个ip.xls的绝对路径+文件名
        :return: {'result': '执行结果'}
        """
        # vuln_data.keys():['端口', '协议', '服务', '漏洞名称', '漏洞风险值', '风险等级', '服务分类','应用分类',
        #                   '系统分类', '威胁分类', '时间分类', 'CVE年份分类', '发现日期', 'CVE编号', 'CNNVD编号',
        #                   'CNCVE编号', 'CNVD编号', '详细描述', '解决办法', '返回信息']
        # Vulnerability_scan.objects.filter(vuln_asset_id=num_id).delete()  # 删除已有漏洞
        v_info = pd.read_excel(filename, sheet_name=1).to_dict()
        if v_info.get('漏洞名称'):
            v_num_id = Vulnerability.get_vuln_id() + 1  # 获取漏洞表id
            rows = len(v_info.get('漏洞名称'))
            for row in range(rows):
                v = {}
                # rsas相同端口和协议是合并行保存的，需要处理
                if str(v_info.get('端口').get(row)) == 'nan':
                    v_info['端口'][row] = str(v_info.get('端口').get(row - 1)).replace('.0', '')
                v['port'] = str(v_info.get('端口').get(row)).replace('.0', '')
                # v['level'] = cls.vuln_severity(v_info.get('风险等级').get(row))
                v['level'] = cls.vuln_severity(v_info.get('漏洞风险值').get(row))
                v['name'] = v_info.get('漏洞名称').get(row)
                v['introduce'] = v_info.get('详细描述').get(row)
                v['fix'] = v_info.get('解决办法').get(row)
                v['cve'] = v_info.get('CVE编号').get(row)
                v['return'] = v_info.get('返回信息').get(row)

                exits = Vulnerability.status(num_id, v['name'], v_num_id)
                v['asset'] = exits['asset']  # 先进行漏洞和资产绑定，避免删除其他资产漏洞
                if exits.get('exits') is True:
                    v['fix_status'] = exits['fix_status']  # 继承漏洞状态
                    Vulnerability.update_or_create(v, exits=True).get('result')
                else:
                    v['fix_status'] = exits['fix_status']
                    v['v_id'] = exits['v_id']
                    v['v_type'] = exits['v_type']
                    Vulnerability.update_or_create(v, exits=False).get('result')
                    v_num_id += 1  # 新建查询漏洞，漏洞id都需要递增

            return {'result': '漏洞导入成功'}
        return {'result': '无漏洞信息'}

    @classmethod
    def report_main(cls, filename, report_type):
        """
        单个IP报告处理主程序
        :param report_type: 漏洞报告类型
        :param filename: 单个ip.xls的绝对路径+文件名
        :return: return {'ip': asset_key, 'port': port_result, 'vulnerability': vuln_result}
        """
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
        asset_type_id = report_type  # 服务器
        asset_score = str(host_info.get('Unnamed: 2').get(1))  # 获取主机风险值,Unnamed: 1所在列的第二个键（不包含首行）
        # asset_type = AssetType.objects.get(id=asset_type_id).name   # 根据asset_type_id获取对应的资产类型名称：如，服务器
        # print('类型名字：' + asset_type)
        exits = Asset.objects.filter(asset_key=asset_key).first()  # 查看唯一值asset_key是否存在
        if not exits:
            try:
                num_id += 1  # num_id还需要用于关联端口,只有IP未创建时才+1，避免影响端口更新，此时导入的IP资产对应最新的id
                asset_id = '01' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(num_id)
                asset_create = Asset.objects.get_or_create(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    asset_type_id=asset_type_id,
                    asset_key=asset_key,
                    asset_score=asset_score,
                    # asset_description=asset_description,
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
            Asset.objects.filter(asset_key=asset_key).update(asset_type=asset_type_id)
        # 更新端口
        port_result = cls.port_update(num_id, filename)
        # 导入漏洞，后续逻辑需要细化
        vuln_result = cls.vlun_add_or_update(num_id, filename)
        return {'ip': asset_key, 'port': port_result, 'vulnerability': vuln_result}
