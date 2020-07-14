# coding:utf-8
'''
Created on 2018年5月24日

@author: yuguanc
'''

from __future__ import absolute_import, unicode_literals
import os
from celery import Celery, platforms
from django.conf import settings
from celery.schedules import crontab
from API.Functions.dinktalk import DinkTalk

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SeMF.settings')

app = Celery('SeMF')

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
# 允许root用户运行celery
platforms.C_FORCE_ROOT = True

# 配置定时任务
app.conf.update(
    timezone='Asia/Shanghai',
    enable_utc=True,
    CELERYBEAT_SCHEDULE={

        # 'sum-task': {
        #     'task': 'deploy.tasks.add',
        #     'schedule':  timedelta(seconds=20),
        #     'args': (5, 6)
        # }
        # 每天04：30执行钉钉通讯录缓存刷新
        'refresh-cache': {
            'task': 'SeMF.refresh_cache',
            # 'schedule': crontab(hour=4, minute=30),
            'schedule': crontab(minute=3),
        }
    }
)


@app.task
def refresh_cache():
    token = DinkTalk.get_assess_token()
    # res = DinkTalk.save_user_list(assess_token=token)
    msg = {"msgtype": "text", "text": {"content": "定时推送测试233——by tachiulam"}}
    info = DinkTalk.corp_conversation(assess_token=token,
                                      user_name_list=['lintechao'],
                                      msg=msg)

# @app.task(bind=True)
# def debug_task(self):
#     print('Request: {0!r}'.format(self.request))

