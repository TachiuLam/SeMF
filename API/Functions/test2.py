#!/usr/bin/python3
# -*- coding : utf-8 -*-
# @Author    : Tachiu Lam
# @Mail      : lintechao@yingzi.com
# @Datetime  : 2020/12/11 10:57
# @Software  : PyCharm

import requests
import json

data = {'type': 'SCANNING_COMPLETED', 'occur_at': 1607654984, 'operator': 'auto', 'event_data': {'resources': [
    {'digest': 'sha256:9db4781eaf30d7cb779a6636c84b5ddd49f02d129c0705feb05ec76eb1dcad00', 'tag': '',
     'resource_url': 'test-harbor.yingzi.com/test/semf:', 'scan_overview': {
        'application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0': {
            'report_id': 'd2f3ffb3-591f-4b59-a6b8-1edef5b79fb4', 'scan_status': 'Success', 'severity': 'Critical',
            'duration': 64, 'summary': {'total': 702, 'fixable': 369,
                                        'summary': {'Critical': 9, 'High': 35, 'Low': 124, 'Medium': 184,
                                                    'Negligible': 299, 'Unknown': 51}},
            'start_time': '2020-12-11T02:48:40.604557Z', 'end_time': '2020-12-11T02:49:44.070851Z',
            'scanner': {'name': 'Clair', 'vendor': 'CoreOS', 'version': '2.x'}, 'complete_percent': 100}}}],
    'repository': {
        'name': 'semf',
        'namespace': 'test',
        'repo_full_name': 'test/semf',
        'repo_type': 'public'}}}

print(data.get('event_data').keys())  # dict_keys(['type', 'occur_at', 'operator', 'event_data'])
resources = data.get('event_data').get('resources')
repository = data.get('event_data').get('repository')
for each in resources:
    sha256 = each.get('digest')
    resource_url = each.get('resource_url').split('/')[0]
    scan_status = each.get('scan_overview').get(
        'application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0').get('scan_status')
    scanner = each.get('scan_overview').get('application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0').get(
        'scanner').get('name')

img_name = repository.get('name')
namespace = repository.get('namespace')
print(sha256, resource_url, scan_status, scanner, img_name, namespace)
api_url = 'http://' + resource_url + '/api/v2.0/projects/' + namespace + '/repositories/' + img_name + '/artifacts/' + sha256 + '/additions/vulnerabilities'
print(api_url)
# api_url = 'http://test-harbor.yingzi.com/api/v2.0/projects/test/repositories/nginx/artifacts/sha256:99d0a53e3718cef59443558607d1e100b325d6a2b678cd2a48b05e5e22ffeb49/additions/vulnerabilities'
res = requests.get(api_url)
print(res.content)
content = json.loads(res.content)
print(content.get("application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"))
