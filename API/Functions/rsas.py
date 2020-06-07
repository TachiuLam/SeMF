# -*- coding: utf-8 -*-
# tachiu lam
# techaolin@gmail.com
# 2020/6/6 10:28 下午
# PyCharm
from AssetManage import models
from SeMF.settings import MEDIA_API
import os, time
import pandas as pd


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

    @classmethod
    def vuln_deal(cls, filename):
        each_ip_data = []
        # sheet json数据格式为去（前行后列）：{(0,0):{(0,1),(0,2)...},(1,0):{(1,1),(1,2)..,}
        # 要取坐标(1,2)单元格的值，则data.get('(1,0)').get(1)

        # vuln_data.keys():['端口', '协议', '服务', '漏洞名称', '漏洞风险值', '风险等级', '服务分类','应用分类',
        #                   '系统分类', '威胁分类', '时间分类', 'CVE年份分类', '发现日期', 'CVE编号', 'CNNVD编号',
        #                   'CNCVE编号', 'CNVD编号', '详细描述', '解决办法', '返回信息']
        vuln_data = pd.read_excel(filename, sheet_name=1).to_dict()
        rows = len(vuln_data.get('漏洞名称'))
        for row in range(rows):
            cls.each_line['Severity'] = cls.vuln_severity(vuln_data.get('风险等级').get(row))
            cls.each_line['NVT Name'] = vuln_data.get('漏洞名称').get(row)
            cls.each_line['CVEs'] = vuln_data.get('CVE编号').get(row) or 'NOCVE'
            cls.each_line['Summary'] = vuln_data.get('详细描述').get(row)
            cls.each_line['Solution'] = vuln_data.get('解决办法').get(row)
            cls.each_line['Other References'] = vuln_data.get('返回信息').get(row)
            cls.each_line['Timestamp'] = '2020-02-16T09:45:31Z'
            # rsas相同端口和协议是合并行保存的，需要处理
            if str(vuln_data.get('端口').get(row)) == 'nan':
                vuln_data['端口'][row] = str(vuln_data.get('端口').get(row - 1)).replace('.0', '')
            cls.each_line['Port'] = str(vuln_data.get('端口').get(row)).replace('.0', '')

            if type(vuln_data.get('服务').get(row)) is float:
                vuln_data['服务'][row] = vuln_data.get('服务').get(row - 1)
            cls.each_line['Port Protocol'] = vuln_data.get('服务').get(row)
            # 添加此字段会导致IP无法归类
            cls.each_line['Specific Result'] = cls.each_line['Port'] + '端口\t' + cls.each_line['Port Protocol']

            cls.each_line['NVT OID'] = '1.3.6.1.4.1.25623.1.0.108560'
            # cls.each_line['Result ID'] = '2f117aff-8209-4e8a-aeb2-b9172724818f'
            cls.each_line['Task ID'] = 'fd2227de-4142-4e3c-b483-8cccd7317078'
            # cls.each_line['Task Name'] = 'RSAS'

            # 写入IP
            host_data = pd.read_excel(filename, sheet_name=0).to_dict()
            try:
                num_id = models.Asset.objects.latest('id').id
            except:
                num_id = 0
            asset_id = '01' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(num_id)
            asset_name = asset_key = asset_description = host_data.get('Unnamed: 1').get(
                1)  # 获取ip地址,Unnamed: 1所在列的第二个键（不包含首行）
            asset_type = '服务器'

            cls.each_line['IP'] = host_data.get('Unnamed: 1').get(1)  # 获取ip地址,Unnamed: 1所在列的第二个键（不包含首行）
            # print(cls.each_line)
            each_line = cls.each_line.copy()  # 直接赋值和copy是有区别的噢
            each_ip_data.append(each_line)  # 浅拷贝赋值地址空间不一致，列表里面内容不会随cls.each_line变化
            cls.clear_each_line()  # 初始化每行格式

        return each_ip_data
