from django.db import models


# Create your models here.
class ThreatIP(models.Model):
    threat_ip = models.CharField('威胁IP', max_length=45)
    threat_type = models.CharField('威胁类型',max_length=45,null=True)
    country = models.CharField('国家', max_length=15,null=True)
    province = models.CharField('省份', max_length=15,null=True)
    city = models.CharField('城市', max_length=15,null=True)
    isp = models.CharField('运营商', max_length=15,null=True)
    longitude = models.CharField('经度', max_length=15,null=True)
    latitude = models.CharField('维度', max_length=15,null=True)
    update_time = models.DateTimeField('修复时间', auto_now=True)

    def __str__(self):
        return self.threat_ip