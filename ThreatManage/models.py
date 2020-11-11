from django.db import models


# Create your models here.
class ThreatIP(models.Model):
    threat_ip = models.CharField('威胁IP', max_length=45, null=True)
    threat_type = models.CharField('威胁类型',max_length=45)
    country = models.CharField('国家', max_length=15)
    province = models.CharField('省份', max_length=15)
    city = models.CharField('城市', max_length=15)
    isp = models.CharField('运营商', max_length=15)
    longitude = models.CharField('经度', max_length=15)
    latitude = models.CharField('维度', max_length=15)
    update_data = models.DateTimeField('修复时间', auto_now=True)
