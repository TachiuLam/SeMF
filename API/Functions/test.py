# -*- coding: utf-8 -*-
# Tachiu Lam
# lintechao@yingzi.com
# 2020/11/18 15:29

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SeMF.settings')
django.setup()
import requests
import json
from django.db.models import Q
from MappedManage.models import Mapped
from API.Functions.send_mail import SendMail
from API.Functions.alert_info import nat_mail_info


false = 1

a = [{"vals": {"publicIp": "103.215.44.132", "protocol": "TCP", "name": "IPservpn", "privatePort": 4009,
               "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.132", "name": "103.215.44.132"},
                                                       {"IP": "172.18.0.10", "name": "172.18.0.10"}],
               "publicPort": 4009,
               "privateIp": "172.18.0.10"},
      "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
               "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.146", "protocol": "TCP", "name": "SDWAN_443_1", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.146", "name": "103.215.44.146"},
                                                          {"IP": "172.18.0.33", "name": "172.18.0.33"}],
                  "publicPort": 443,
                  "privateIp": "172.18.0.33"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.151", "protocol": "TCP", "name": "kefu_1", "privatePort": 8888,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.151", "name": "117.48.196.151"},
                                                          {"IP": "172.18.111.10", "name": "172.18.111.10"}],
                  "publicPort": 8888, "privateIp": "172.18.111.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.151", "protocol": "TCP", "name": "kefu_2", "privatePort": 8093,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.151", "name": "117.48.196.151"},
                                                          {"IP": "172.18.111.10", "name": "172.18.111.10"}],
                  "publicPort": 8093, "privateIp": "172.18.111.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.151", "protocol": "TCP", "name": "kefu_3", "privatePort": 9010,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.151", "name": "117.48.196.151"},
                                                          {"IP": "172.18.111.10", "name": "172.18.111.10"}],
                  "publicPort": 9010, "privateIp": "172.18.111.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "weixin-program-80_lt", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.20.200", "name": "172.18.20.200"}],
                  "publicPort": 80, "privateIp": "172.18.20.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.150", "protocol": "TCP", "name": "weixin-program-80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.150", "name": "103.215.44.150"},
                                                          {"IP": "172.18.20.200", "name": "172.18.20.200"}],
                  "publicPort": 80, "privateIp": "172.18.20.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.150", "protocol": "TCP", "name": "weixin-program--443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.150", "name": "103.215.44.150"},
                                                          {"IP": "172.18.20.200", "name": "172.18.20.200"}],
                  "publicPort": 443, "privateIp": "172.18.20.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.132", "protocol": "TCP", "name": "weixin-program--8080", "privatePort": 8080,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.132", "name": "103.215.44.132"},
                                                          {"IP": "172.18.20.200", "name": "172.18.20.200"}],
                  "publicPort": 8080, "privateIp": "172.18.20.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.151", "protocol": "TCP", "name": "yufabu-huanjing-80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.151", "name": "103.215.44.151"},
                                                          {"IP": "172.18.132.61", "name": "172.18.132.61"}],
                  "publicPort": 80, "privateIp": "172.18.132.61"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.151", "protocol": "TCP", "name": "yufabu-huanjing-443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.151", "name": "103.215.44.151"},
                                                          {"IP": "172.18.132.61", "name": "172.18.132.61"}],
                  "publicPort": 443, "privateIp": "172.18.132.61"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.142", "protocol": "TCP", "name": "K8S_Pre-pro_80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.142", "name": "117.48.196.142"},
                                                          {"IP": "172.18.132.60", "name": "172.18.132.60"}],
                  "publicPort": 80, "privateIp": "172.18.132.60"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "weixin-program--443_lt", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.20.200", "name": "172.18.20.200"}],
                  "publicPort": 443, "privateIp": "172.18.20.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.76", "protocol": "TCP", "name": "SDWAN_443_2", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.76", "name": "112.93.114.76"},
                                                          {"IP": "172.18.0.34", "name": "172.18.0.34"}],
                  "publicPort": 443,
                  "privateIp": "172.18.0.34"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.150", "protocol": "TCP", "name": "yanshi-kafka1", "privatePort": 9094,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.150", "name": "103.215.44.150"},
                                                          {"IP": "172.18.112.44", "name": "172.18.112.44"}],
                  "publicPort": 9094, "privateIp": "172.18.112.44"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.150", "protocol": "TCP", "name": "yanshi-kafka2", "privatePort": 9094,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.150", "name": "103.215.44.150"},
                                                          {"IP": "172.18.112.45", "name": "172.18.112.45"}],
                  "publicPort": 9095, "privateIp": "172.18.112.45"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.150", "protocol": "TCP", "name": "yanshi-kafka3", "privatePort": 9094,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.150", "name": "103.215.44.150"},
                                                          {"IP": "172.18.112.46", "name": "172.18.112.46"}],
                  "publicPort": 9096, "privateIp": "172.18.112.46"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.152", "protocol": "TCP", "name": "im_produce", "privatePort": 8093,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.152", "name": "103.215.44.152"},
                                                          {"IP": "172.18.30.253", "name": "172.18.30.253"}],
                  "publicPort": 8093, "privateIp": "172.18.30.253"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.146", "protocol": "UDP", "name": "SDWAN_2426_1", "privatePort": 2426,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.146", "name": "103.215.44.146"},
                                                          {"IP": "172.18.0.33", "name": "172.18.0.33"}],
                  "publicPort": 2426,
                  "privateIp": "172.18.0.33"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.76", "protocol": "UDP", "name": "SDWAN_2426_2", "privatePort": 2426,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.76", "name": "112.93.114.76"},
                                                          {"IP": "172.18.0.34", "name": "172.18.0.34"}],
                  "publicPort": 2426,
                  "privateIp": "172.18.0.34"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.154", "protocol": "TCP", "name": "k8s_dev-tcp21666", "privatePort": 21666,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.154", "name": "117.48.196.154"},
                                                          {"IP": "172.21.10.26", "name": "172.21.10.26"}],
                  "publicPort": 21666, "privateIp": "172.21.10.26"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.153", "protocol": "TCP", "name": "yanshi-YingxinIM01", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.153", "name": "103.215.44.153"},
                                                          {"IP": "172.18.112.41", "name": "172.18.112.41"}],
                  "publicPort": 443, "privateIp": "172.18.112.41"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.144", "protocol": "TCP", "name": "K8S_mqtt_40010tcp", "privatePort": 40010,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.144", "name": "117.48.196.144"},
                                                          {"IP": "172.18.33.103", "name": "172.18.33.103"}],
                  "publicPort": 40010, "privateIp": "172.18.33.103"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.144", "protocol": "TCP", "name": "K8S_mqtt_40011tcp", "privatePort": 40011,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.144", "name": "117.48.196.144"},
                                                          {"IP": "172.18.33.103", "name": "172.18.33.103"}],
                  "publicPort": 40011, "privateIp": "172.18.33.103"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.144", "protocol": "TCP", "name": "K8S_mqtt_40012tcp", "privatePort": 40012,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.144", "name": "117.48.196.144"},
                                                          {"IP": "172.18.33.103", "name": "172.18.33.103"}],
                  "publicPort": 40012, "privateIp": "172.18.33.103"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.144", "protocol": "TCP", "name": "K8S_mqtt_40013tcp", "privatePort": 40013,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.144", "name": "117.48.196.144"},
                                                          {"IP": "172.18.33.103", "name": "172.18.33.103"}],
                  "publicPort": 40013, "privateIp": "172.18.33.103"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.144", "protocol": "TCP", "name": "K8S_Entrance_80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.144", "name": "117.48.196.144"},
                                                          {"IP": "172.18.132.90", "name": "172.18.132.90"}],
                  "publicPort": 80, "privateIp": "172.18.132.90"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.152", "protocol": "TCP", "name": "IM-43210", "privatePort": 43210,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.152", "name": "103.215.44.152"},
                                                          {"IP": "172.18.30.253", "name": "172.18.30.253"}],
                  "publicPort": 43210, "privateIp": "172.18.30.253"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.144", "protocol": "TCP", "name": "K8S_Entrance_443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.144", "name": "117.48.196.144"},
                                                          {"IP": "172.18.132.90", "name": "172.18.132.90"}],
                  "publicPort": 443, "privateIp": "172.18.132.90"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.142", "protocol": "TCP", "name": "K8S_Pre-pro_40010", "privatePort": 40010,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.142", "name": "117.48.196.142"},
                                                          {"IP": "172.18.34.101", "name": "172.18.34.101"}],
                  "publicPort": 40010, "privateIp": "172.18.34.101"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.148", "protocol": "TCP", "name": "kong-dev_80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.148", "name": "103.215.44.148"},
                                                          {"IP": "172.18.132.12", "name": "172.18.132.12"}],
                  "publicPort": 80, "privateIp": "172.18.132.12"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.147", "protocol": "TCP", "name": "kong-pro_443_CT", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.147", "name": "103.215.44.147"},
                                                          {"IP": "172.18.129.249", "name": "172.18.129.249"}],
                  "publicPort": 443, "privateIp": "172.18.129.249"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "183.240.42.60", "protocol": "TCP", "name": "kong-pro_443_CM", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "183.240.42.60", "name": "183.240.42.60"},
                                                          {"IP": "172.18.132.91", "name": "172.18.132.91"}],
                  "publicPort": 443, "privateIp": "172.18.132.91"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.72", "protocol": "TCP", "name": "yufabu-huanjing80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.72", "name": "112.93.114.72"},
                                                          {"IP": "172.18.132.61", "name": "172.18.132.61"}],
                  "publicPort": 80, "privateIp": "172.18.132.61"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.72", "protocol": "TCP", "name": "yufabu-huanjing443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.72", "name": "112.93.114.72"},
                                                          {"IP": "172.18.132.61", "name": "172.18.132.61"}],
                  "publicPort": 443, "privateIp": "172.18.132.61"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.147", "protocol": "TCP", "name": "kong-pro_80_CT", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.147", "name": "103.215.44.147"},
                                                          {"IP": "172.18.129.249", "name": "172.18.129.249"}],
                  "publicPort": 80, "privateIp": "172.18.129.249"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.73", "protocol": "TCP", "name": "kong-pro-lt80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.73", "name": "112.93.114.73"},
                                                          {"IP": "172.18.132.91", "name": "172.18.132.91"}],
                  "publicPort": 80, "privateIp": "172.18.132.91"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "183.240.42.60", "protocol": "TCP", "name": "kong-pro_80_CM", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "183.240.42.60", "name": "183.240.42.60"},
                                                          {"IP": "172.18.132.91", "name": "172.18.132.91"}],
                  "publicPort": 80, "privateIp": "172.18.132.91"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.73", "protocol": "TCP", "name": "kong-pro-lt443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.73", "name": "112.93.114.73"},
                                                          {"IP": "172.18.132.91", "name": "172.18.132.91"}],
                  "publicPort": 443, "privateIp": "172.18.132.91"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.154", "protocol": "TCP", "name": "k8s_dev-test-80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.154", "name": "117.48.196.154"},
                                                          {"IP": "172.18.132.11", "name": "172.18.132.11"}],
                  "publicPort": 80, "privateIp": "172.18.132.11"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.154", "protocol": "TCP", "name": "k8s_dev-test-443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.154", "name": "117.48.196.154"},
                                                          {"IP": "172.18.132.11", "name": "172.18.132.11"}],
                  "publicPort": 443, "privateIp": "172.18.132.11"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.142", "protocol": "ICMP", "name": "K8S_Pre-pro_icmp", "privatePort": "",
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.142", "name": "117.48.196.142"},
                                                          {"IP": "172.18.34.101", "name": "172.18.34.101"}],
                  "publicPort": "", "privateIp": "172.18.34.101"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.144", "protocol": "ICMP", "name": "K8S_mqtt_icmp", "privatePort": "",
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.144", "name": "117.48.196.144"},
                                                          {"IP": "172.18.33.103", "name": "172.18.33.103"}],
                  "publicPort": "", "privateIp": "172.18.33.103"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.148", "protocol": "TCP", "name": "kong-dev_443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.148", "name": "103.215.44.148"},
                                                          {"IP": "172.18.132.12", "name": "172.18.132.12"}],
                  "publicPort": 443, "privateIp": "172.18.132.12"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.149", "protocol": "TCP", "name": "kong-test_80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.149", "name": "103.215.44.149"},
                                                          {"IP": "172.18.132.13", "name": "172.18.132.13"}],
                  "publicPort": 80, "privateIp": "172.18.132.13"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.149", "protocol": "TCP", "name": "kong-test_443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.149", "name": "103.215.44.149"},
                                                          {"IP": "172.18.132.13", "name": "172.18.132.13"}],
                  "publicPort": 443, "privateIp": "172.18.132.13"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.156", "protocol": "TCP", "name": "mail-yingzi-dx04", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.156", "name": "103.215.44.156"},
                                                          {"IP": "172.18.132.92", "name": "172.18.132.92"}],
                  "publicPort": 80, "privateIp": "172.18.132.92"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.156", "protocol": "TCP", "name": "mail-yingzi-dx05", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.156", "name": "103.215.44.156"},
                                                          {"IP": "172.18.132.92", "name": "172.18.132.92"}],
                  "publicPort": 443, "privateIp": "172.18.132.92"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.77", "protocol": "TCP", "name": "mail-yingzi-lt04", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.77", "name": "112.93.114.77"},
                                                          {"IP": "172.18.132.92", "name": "172.18.132.92"}],
                  "publicPort": 80, "privateIp": "172.18.132.92"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.132", "protocol": "UDP", "name": "IPservpn_2", "privatePort": 4009,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.132", "name": "103.215.44.132"},
                                                          {"IP": "172.18.0.10", "name": "172.18.0.10"}],
                  "publicPort": 4009,
                  "privateIp": "172.18.0.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.77", "protocol": "TCP", "name": "mail-yingzi-lt05", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.77", "name": "112.93.114.77"},
                                                          {"IP": "172.18.132.92", "name": "172.18.132.92"}],
                  "publicPort": 443, "privateIp": "172.18.132.92"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.147", "protocol": "TCP", "name": "kong-pro_80_BGP", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.147", "name": "117.48.196.147"},
                                                          {"IP": "172.18.132.91", "name": "172.18.132.91"}],
                  "publicPort": 80, "privateIp": "172.18.132.91"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "yanshi-kafka1_lt", "privatePort": 9094,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.112.44", "name": "172.18.112.44"}],
                  "publicPort": 9094, "privateIp": "172.18.112.44"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "yanshi-kafka2_lt", "privatePort": 9094,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.112.45", "name": "172.18.112.45"}],
                  "publicPort": 9095, "privateIp": "172.18.112.45"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "yanshi-kafka3_lt", "privatePort": 9094,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.112.46", "name": "172.18.112.46"}],
                  "publicPort": 9096, "privateIp": "172.18.112.46"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.142", "protocol": "TCP", "name": "K8S_Pre-pro_443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.142", "name": "117.48.196.142"},
                                                          {"IP": "172.18.132.60", "name": "172.18.132.60"}],
                  "publicPort": 443, "privateIp": "172.18.132.60"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.144", "protocol": "TCP", "name": "K8S_mqtt_40014tcp", "privatePort": 40014,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.144", "name": "117.48.196.144"},
                                                          {"IP": "172.18.33.103", "name": "172.18.33.103"}],
                  "publicPort": 40014, "privateIp": "172.18.33.103"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.142", "protocol": "TCP", "name": "yingzi-iot-zhyc-gateway-adapter.stage",
                  "privatePort": 21666, "firewall": "172.18.0.6",
                  "IPADDRESS": [{"IP": "117.48.196.142", "name": "117.48.196.142"},
                                {"IP": "172.18.34.101", "name": "172.18.34.101"}], "publicPort": 21666,
                  "privateIp": "172.18.34.101"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "kafka_prod.yingzi.com-9098_lt",
                  "privatePort": 9092, "firewall": "172.18.0.6",
                  "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                {"IP": "172.18.32.12", "name": "172.18.32.12"}], "publicPort": 9098,
                  "privateIp": "172.18.32.12"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "kafka.yingzi.com-9097_lt",
                  "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.32.11", "name": "172.18.32.11"}],
                  "publicPort": 9097, "privateIp": "172.18.32.11"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.147", "protocol": "TCP", "name": "kong-pro_443_BGP", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.147", "name": "117.48.196.147"},
                                                          {"IP": "172.18.132.91", "name": "172.18.132.91"}],
                  "publicPort": 443, "privateIp": "172.18.132.91"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.135", "protocol": "TCP", "name": "guanwang-waf-80", "privatePort": 80,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.135", "name": "117.48.196.135"},
                                                          {"IP": "172.18.132.93", "name": "172.18.132.93"}],
                  "publicPort": 80, "privateIp": "172.18.132.93"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.135", "protocol": "TCP", "name": "guanwang-waf-443", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.135", "name": "117.48.196.135"},
                                                          {"IP": "172.18.132.93", "name": "172.18.132.93"}],
                  "publicPort": 443, "privateIp": "172.18.132.93"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.158", "protocol": "UDP", "name": "openvpn", "privatePort": 11194,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.158", "name": "117.48.196.158"},
                                                          {"IP": "172.20.200.102", "name": "172.20.200.102"}],
                  "publicPort": 11194, "privateIp": "172.20.200.102"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.158", "protocol": "ICMP", "name": "openvpnICMP", "privatePort": "",
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.158", "name": "117.48.196.158"},
                                                          {"IP": "172.20.200.102", "name": "172.20.200.102"}],
                  "publicPort": "", "privateIp": "172.20.200.102"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.74", "protocol": "TCP", "name": "yanshi-YingxinIM01_lt", "privatePort": 443,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.74", "name": "112.93.114.74"},
                                                          {"IP": "172.18.112.41", "name": "172.18.112.41"}],
                  "publicPort": 443, "privateIp": "172.18.112.41"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.150", "protocol": "TCP", "name": "kafka.yingzi.com-9097", "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.150", "name": "103.215.44.150"},
                                                          {"IP": "172.18.32.11", "name": "172.18.32.11"}],
                  "publicPort": 7071, "privateIp": "172.18.32.11"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.150", "protocol": "TCP", "name": "kafka.yingzi.com-9098", "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.150", "name": "103.215.44.150"},
                                                          {"IP": "172.18.32.12", "name": "172.18.32.12"}],
                  "publicPort": 7072, "privateIp": "172.18.32.12"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.150", "protocol": "TCP", "name": "kafka.yingzi.com-9099", "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.150", "name": "103.215.44.150"},
                                                          {"IP": "172.18.32.13", "name": "172.18.32.13"}],
                  "publicPort": 7073, "privateIp": "172.18.32.13"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.156", "protocol": "TCP", "name": "mail-yingzi-dx01", "privatePort": 110,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.156", "name": "103.215.44.156"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 110, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.156", "protocol": "TCP", "name": "mail-yingzi-dx02", "privatePort": 143,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.156", "name": "103.215.44.156"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 143, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.156", "protocol": "TCP", "name": "mail-yingzi-dx07", "privatePort": 465,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.156", "name": "103.215.44.156"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 465, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.156", "protocol": "TCP", "name": "mail-yingzi-dx08", "privatePort": 993,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.156", "name": "103.215.44.156"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 993, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.156", "protocol": "TCP", "name": "mail-yingzi-dx03", "privatePort": 25,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.156", "name": "103.215.44.156"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 25, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "103.215.44.156", "protocol": "TCP", "name": "mail-yingzi-dx06", "privatePort": 995,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "103.215.44.156", "name": "103.215.44.156"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 995, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.77", "protocol": "TCP", "name": "mail-yingzi-lt01", "privatePort": 110,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.77", "name": "112.93.114.77"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 110, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.77", "protocol": "TCP", "name": "mail-yingzi-lt02", "privatePort": 143,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.77", "name": "112.93.114.77"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 143, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.77", "protocol": "TCP", "name": "mail-yingzi-lt03", "privatePort": 25,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.77", "name": "112.93.114.77"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 25, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.77", "protocol": "TCP", "name": "mail-yingzi-lt06", "privatePort": 995,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.77", "name": "112.93.114.77"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 995, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.77", "protocol": "TCP", "name": "mail-yingzi-lt07", "privatePort": 465,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.77", "name": "112.93.114.77"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 465, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.77", "protocol": "TCP", "name": "mail-yingzi-lt08", "privatePort": 993,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.77", "name": "112.93.114.77"},
                                                          {"IP": "172.18.129.10", "name": "172.18.129.10"}],
                  "publicPort": 993, "privateIp": "172.18.129.10"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "kafka.yingzi.com-9097_Lt",
                  "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.32.11", "name": "172.18.32.11"}],
                  "publicPort": 7071, "privateIp": "172.18.32.11"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "kafka.yingzi.com-9098_lt",
                  "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.32.12", "name": "172.18.32.12"}],
                  "publicPort": 7072, "privateIp": "172.18.32.12"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "112.93.114.71", "protocol": "TCP", "name": "kafka.yingzi.com-9099_lt",
                  "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "112.93.114.71", "name": "112.93.114.71"},
                                                          {"IP": "172.18.32.13", "name": "172.18.32.13"}],
                  "publicPort": 7073, "privateIp": "172.18.32.13"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.152", "protocol": "TCP", "name": "im_produce_BGP", "privatePort": 8093,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.152", "name": "117.48.196.152"},
                                                          {"IP": "172.18.30.253", "name": "172.18.30.253"}],
                  "publicPort": 8093, "privateIp": "172.18.30.253"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.152", "protocol": "TCP", "name": "IM-43210_BGP", "privatePort": 43210,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.152", "name": "117.48.196.152"},
                                                          {"IP": "172.18.30.253", "name": "172.18.30.253"}],
                  "publicPort": 43210, "privateIp": "172.18.30.253"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.150", "protocol": "TCP", "name": "kafka.yingzi.com-9097_BGP",
                  "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.150", "name": "117.48.196.150"},
                                                          {"IP": "172.18.32.11", "name": "172.18.32.11"}],
                  "publicPort": 7071, "privateIp": "172.18.32.11"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.150", "protocol": "TCP", "name": "kafka.yingzi.com-9098_BGP",
                  "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.150", "name": "117.48.196.150"},
                                                          {"IP": "172.18.32.12", "name": "172.18.32.12"}],
                  "publicPort": 7072, "privateIp": "172.18.32.12"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.150", "protocol": "TCP", "name": "kafka.yingzi.com-9099_BGP",
                  "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.150", "name": "117.48.196.150"},
                                                          {"IP": "172.18.32.13", "name": "172.18.32.13"}],
                  "publicPort": 7073, "privateIp": "172.18.32.13"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.153", "protocol": "TCP", "name": "kafka_pre_pro_dongsheng_4_BGP",
                  "privatePort": 9092, "firewall": "172.18.0.6",
                  "IPADDRESS": [{"IP": "117.48.196.153", "name": "117.48.196.153"},
                                {"IP": "172.18.113.96", "name": "172.18.113.96"}], "publicPort": 8094,
                  "privateIp": "172.18.113.96"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.153", "protocol": "TCP", "name": "kafka_pre_pro_dongsheng_5_BGP",
                  "privatePort": 9092, "firewall": "172.18.0.6",
                  "IPADDRESS": [{"IP": "117.48.196.153", "name": "117.48.196.153"},
                                {"IP": "172.18.113.97", "name": "172.18.113.97"}], "publicPort": 8095,
                  "privateIp": "172.18.113.97"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.153", "protocol": "TCP", "name": "kafka_pre_pro_dongsheng_6_BGP",
                  "privatePort": 9092, "firewall": "172.18.0.6",
                  "IPADDRESS": [{"IP": "117.48.196.153", "name": "117.48.196.153"},
                                {"IP": "172.18.113.98", "name": "172.18.113.98"}], "publicPort": 8096,
                  "privateIp": "172.18.113.98"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.149", "protocol": "TCP", "name": "thirdparty_BGP_kafka", "privatePort": 9092,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.149", "name": "117.48.196.149"},
                                                          {"IP": "172.18.40.200", "name": "172.18.40.200"}],
                  "publicPort": 9092, "privateIp": "172.18.40.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.149", "protocol": "TCP", "name": "thirdparty_BGP_mosquitto",
                  "privatePort": 1883,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.149", "name": "117.48.196.149"},
                                                          {"IP": "172.18.40.200", "name": "172.18.40.200"}],
                  "publicPort": 1883, "privateIp": "172.18.40.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.149", "protocol": "TCP", "name": "thirdparty_BGP_location1",
                  "privatePort": 9080,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.149", "name": "117.48.196.149"},
                                                          {"IP": "172.18.40.200", "name": "172.18.40.200"}],
                  "publicPort": 9080, "privateIp": "172.18.40.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.149", "protocol": "TCP", "name": "thirdparty_BGP_location2",
                  "privatePort": 9070,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.149", "name": "117.48.196.149"},
                                                          {"IP": "172.18.40.200", "name": "172.18.40.200"}],
                  "publicPort": 9070, "privateIp": "172.18.40.200"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.143", "protocol": "TCP", "name": "IPGuard_8100", "privatePort": 8100,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.143", "name": "117.48.196.143"},
                                                          {"IP": "172.18.129.120", "name": "172.18.129.120"}],
                  "publicPort": 8100, "privateIp": "172.18.129.120"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.142", "protocol": "TCP", "name": "K8S_Pre-pro_40000", "privatePort": 40000,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.142", "name": "117.48.196.142"},
                                                          {"IP": "172.18.34.101", "name": "172.18.34.101"}],
                  "publicPort": 40000, "privateIp": "172.18.34.101"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.142", "protocol": "TCP", "name": "K8S_Pre-pro_40001", "privatePort": 40001,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.142", "name": "117.48.196.142"},
                                                          {"IP": "172.18.34.101", "name": "172.18.34.101"}],
                  "publicPort": 40001, "privateIp": "172.18.34.101"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "117.48.196.142", "protocol": "UDP", "name": "K8S_Pre-pro_29231", "privatePort": 29231,
                  "firewall": "172.18.0.6", "IPADDRESS": [{"IP": "117.48.196.142", "name": "117.48.196.142"},
                                                          {"IP": "172.18.34.101", "name": "172.18.34.101"}],
                  "publicPort": 29231, "privateIp": "172.18.34.101"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.165", "protocol": "UDP", "name": "GXIPservpn_2", "privatePort": 4009,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.165", "name": "61.140.16.165"},
                                                          {"IP": "172.19.0.20", "name": "172.19.0.20"}],
                  "publicPort": 4009,
                  "privateIp": "172.19.0.20"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.165", "protocol": "TCP", "name": "GXIPsecvpn", "privatePort": 4009,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.165", "name": "61.140.16.165"},
                                                          {"IP": "172.19.0.20", "name": "172.19.0.20"}],
                  "publicPort": 4009,
                  "privateIp": "172.19.0.20"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.162", "protocol": "TCP", "name": "Safe-app", "privatePort": 8265,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.162", "name": "61.140.16.162"},
                                                          {"IP": "172.19.128.20", "name": "172.19.128.20"}],
                  "publicPort": 8265, "privateIp": "172.19.128.20"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "119.32.28.5", "protocol": "TCP", "name": "safe", "privatePort": 8265,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "119.32.28.5", "name": "119.32.28.5"},
                                                          {"IP": "172.19.128.20", "name": "172.19.128.20"}],
                  "publicPort": 8265, "privateIp": "172.19.128.20"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.164", "protocol": "ICMP", "name": "Safe-app1", "privatePort": "",
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.164", "name": "61.140.16.164"},
                                                          {"IP": "172.19.128.20", "name": "172.19.128.20"}],
                  "publicPort": "", "privateIp": "172.19.128.20"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.165", "protocol": "ICMP", "name": "Pig_Farm_Video_FTP_icmp", "privatePort": "",
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.165", "name": "61.140.16.165"},
                                                          {"IP": "172.19.128.17", "name": "172.19.128.17"}],
                  "publicPort": "", "privateIp": "172.19.128.17"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.164", "protocol": "TCP", "name": "FPF:7094", "privatePort": 9094,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.164", "name": "61.140.16.164"},
                                                          {"IP": "172.19.100.43", "name": "172.19.100.43"}],
                  "publicPort": 7094, "privateIp": "172.19.100.43"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.164", "protocol": "TCP", "name": "FPF:7095", "privatePort": 9094,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.164", "name": "61.140.16.164"},
                                                          {"IP": "172.19.100.44", "name": "172.19.100.44"}],
                  "publicPort": 7095, "privateIp": "172.19.100.44"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.164", "protocol": "TCP", "name": "FPF:7096", "privatePort": 9094,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.164", "name": "61.140.16.164"},
                                                          {"IP": "172.19.100.45", "name": "172.19.100.45"}],
                  "publicPort": 7096, "privateIp": "172.19.100.45"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.164", "protocol": "TCP", "name": "SDWAN_443_1", "privatePort": 443,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.164", "name": "61.140.16.164"},
                                                          {"IP": "172.19.0.33", "name": "172.19.0.33"}],
                  "publicPort": 443,
                  "privateIp": "172.19.0.33"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "119.32.28.4", "protocol": "TCP", "name": "SDWAN_443_2", "privatePort": 443,
                  "firewall": "172.19.0.6",
                  "IPADDRESS": [{"IP": "119.32.28.4", "name": "119.32.28.4"},
                                {"IP": "172.19.0.34", "name": "172.19.0.34"}],
                  "publicPort": 443, "privateIp": "172.19.0.34"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "61.140.16.164", "protocol": "UDP", "name": "SDWAN_2426_1", "privatePort": 2426,
                  "firewall": "172.19.0.6", "IPADDRESS": [{"IP": "61.140.16.164", "name": "61.140.16.164"},
                                                          {"IP": "172.19.0.33", "name": "172.19.0.33"}],
                  "publicPort": 2426,
                  "privateIp": "172.19.0.33"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}, {
         "vals": {"publicIp": "119.32.28.4", "protocol": "UDP", "name": "SDWAN_2426_2", "privatePort": 2426,
                  "firewall": "172.19.0.6",
                  "IPADDRESS": [{"IP": "119.32.28.4", "name": "119.32.28.4"},
                                {"IP": "172.19.0.34", "name": "172.19.0.34"}],
                  "publicPort": 2426, "privateIp": "172.19.0.34"},
         "dims": {"pks": ["name", "publicIp", "privateIp", "protocol", "publicPort", "privatePort", "firewall"],
                  "object_id": "SERVER_MAPPING", "upsert": false}}]

content = '防火墙发现不在白名单内的服务器NAT映射！！'+'\n'
for num, each in enumerate(a):
    print(num, each.get('vals'), '\n', each.get('vals').get('publicIp'), each.get('vals').get('publicPort'),
          each.get('vals').get('privateIp'), each.get('vals').get('privatePort'))
    publicIp = str(each.get('vals').get('publicIp'))
    publicPort = str(each.get('vals').get('publicPort'))
    privateIp = str(each.get('vals').get('privateIp'))
    privatePort = str(each.get('vals').get('privatePort'))

    mappedlist = Mapped.objects.filter(
        Q(LANip__asset_key__icontains=privateIp) | Q(WANip__asset_key__icontains=publicIp) | Q(
            LANPort__port__icontains=privatePort) | Q(WANPort__port__icontains=publicPort))
    if not mappedlist.exists():
        content += (privateIp+ '\t'+privatePort+'\t'+publicIp+'\t'+publicPort+'\n')
# print(content)
# nat_mail_info['content'] = content
# SendMail.send_mail(nat_mail_info)

d_url = 'http://127.0.0.1:8000/api/nat/upload/'
r_token = "Token eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InJvb3QiLCJzaXRlIjoia" \
          "HR0cDovL2xvY2FsaG9zdDo4MDAwIn0.11V46DHb5LHsdqVbKuO6d79qZZQGwOeDMakSFfK_aj8"
info = json.dumps(a)
print(type(info),info)

data = {
        'data': info
    }
headers = {
        "Authorization": r_token
    }
# res = requests.post(url=d_url, data=data, headers=headers)
# print(res.text)
# print(data)

from API.Functions.dingtalk import DinkTalk
from API.Functions.dingtalk_msg import DingTalkMsg
from .alert_info import dingtalk_info

msg = {'tittle': '', 'content': '\n'}
msg['tittle'] = '发现新的服务器NAT映射！！！'
username_list = dingtalk_info.get('username_list')
nat_msg = DingTalkMsg.card_msg(msg)
