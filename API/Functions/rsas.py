# -*- coding: utf-8 -*-
# tachiu lam
# techaolin@gmail.com
# 2020/6/6 10:28 下午
# PyCharm
from AssetManage import models
from SeMF.settings import MEDIA_API
import pandas as pd
import os, time


class RSAS:
    """处理绿盟极光扫描器报告/.html格式"""

    @staticmethod
    def end_with(path=None):
        """
        获得路径下所有.xls文件的绝对路径
        :param path:
        :return:
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

    @staticmethod
    def port_add_or_update(num_id, filename):
        """根据asset_key即IP刷新该主机开放端口:删除旧端口、添加新端口"""
        models.Port_Info.objects.filter(asset_id=num_id).delete()   # 删除已有端口

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
                    models.Port_Info.objects.get_or_create(
                        port=port,
                        product=port_product,
                        port_info=port_info,
                        asset_id=num_id,
                    )
                    k += 1
            return {'result': '端口更新成功'}
        return {'result': '无端口信息'}

    @staticmethod
    def add_vlun(filename):
        """关联漏洞信息，漏洞信息只新增不自动删除"""
        # vuln_data.keys():['端口', '协议', '服务', '漏洞名称', '漏洞风险值', '风险等级', '服务分类','应用分类',
        #                   '系统分类', '威胁分类', '时间分类', 'CVE年份分类', '发现日期', 'CVE编号', 'CNNVD编号',
        #                   'CNCVE编号', 'CNVD编号', '详细描述', '解决办法', '返回信息']
        v_info = pd.read_excel(filename, sheet_name=1).to_dict()
        # 明天再搞
        pass

    @classmethod
    def report_main(cls, filename):
        each_ip_data = []
        # sheet json数据格式为去（前行后列）：{(0,0):{(0,1),(0,2)...},(1,0):{(1,1),(1,2)..,}
        # 要取坐标(1,2)单元格的值，则data.get('(1,0)').get(1)

        # vuln_data.keys():['端口', '协议', '服务', '漏洞名称', '漏洞风险值', '风险等级', '服务分类','应用分类',
        #                   '系统分类', '威胁分类', '时间分类', 'CVE年份分类', '发现日期', 'CVE编号', 'CNNVD编号',
        #                   'CNCVE编号', 'CNVD编号', '详细描述', '解决办法', '返回信息']
        # vuln_data = pd.read_excel(filename, sheet_name=1).to_dict()
        # rows = len(vuln_data.get('漏洞名称'))
        # for row in range(rows):
        #     cls.each_line['Severity'] = cls.vuln_severity(vuln_data.get('风险等级').get(row))
        #     cls.each_line['NVT Name'] = vuln_data.get('漏洞名称').get(row)
        #     cls.each_line['CVEs'] = vuln_data.get('CVE编号').get(row) or 'NOCVE'
        #     cls.each_line['Summary'] = vuln_data.get('详细描述').get(row)
        #     cls.each_line['Solution'] = vuln_data.get('解决办法').get(row)
        #     cls.each_line['Other References'] = vuln_data.get('返回信息').get(row)
        #     cls.each_line['Timestamp'] = '2020-02-16T09:45:31Z'
        #     # rsas相同端口和协议是合并行保存的，需要处理
        #     if str(vuln_data.get('端口').get(row)) == 'nan':
        #         vuln_data['端口'][row] = str(vuln_data.get('端口').get(row - 1)).replace('.0', '')
        #     cls.each_line['Port'] = str(vuln_data.get('端口').get(row)).replace('.0', '')
        #
        #     if type(vuln_data.get('服务').get(row)) is float:
        #         vuln_data['服务'][row] = vuln_data.get('服务').get(row - 1)
        #     cls.each_line['Port Protocol'] = vuln_data.get('服务').get(row)
        #     # 添加此字段会导致IP无法归类
        #     cls.each_line['Specific Result'] = cls.each_line['Port'] + '端口\t' + cls.each_line['Port Protocol']
        #
        #     cls.each_line['NVT OID'] = '1.3.6.1.4.1.25623.1.0.108560'
        #     # cls.each_line['Result ID'] = '2f117aff-8209-4e8a-aeb2-b9172724818f'
        #     cls.each_line['Task ID'] = 'fd2227de-4142-4e3c-b483-8cccd7317078'
        #     # cls.each_line['Task Name'] = 'RSAS'

        # 导入IP资产
        host_info = pd.read_excel(filename, sheet_name=0).to_dict()
        try:
            num_id = models.Asset.objects.latest('id').id
        except:
            num_id = 0

        asset_name = asset_key = asset_description = host_info.get('Unnamed: 1').get(
            1)  # 获取ip地址,Unnamed: 1所在列的第二个键（不包含首行）
        asset_type_id = 5  # 服务器

        asset_ip = models.Asset.objects.filter(asset_key=asset_key).first()  # 查看唯一值asset_key是否存在
        if not asset_ip:
            try:
                num_id += 1  # num_id还需要用于关联端口,只有IP未创建时才+1，避免影响端口更新
                asset_id = '01' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(num_id)
                asset_create = models.Asset.objects.get_or_create(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    asset_type_id=asset_type_id,
                    asset_key=asset_key,
                    asset_description=asset_description,
                )
                # asset_create = (<Asset: asset_key>, True)
                if asset_create[1]:
                    asset_create[0].save()
            except Exception as error:
                print(error)
                pass
            return {'ip': None, 'id': None}
        # 更新端口
        result = cls.port_add_or_update(num_id, filename)
        return {'ip': asset_key, 'result': result}


if __name__ == '__main__':
    file1 = r'C:\Users\lintechao\Downloads\711_2020扫描1.0.2_2020_05_09_xls'
    fl = RSAS.end_with(file1)
    for f in fl:
        RSAS.report_main(f)
        RSAS.port_add_or_update('ip', f)
