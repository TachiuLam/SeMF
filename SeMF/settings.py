# coding:utf-8
"""
Django settings for SeMF project.

Generated by 'django-admin startproject' using Django 2.0.4.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '5o@#+%b-%j_-47tzgdy6-e#hz+cu%*^#0$^%(2*ie!7++=&a)%'
# jwt加密算法
ALGORITHM = 'HS256'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']
REGEX_URL = '{url}'  # url作严格匹配
# 设置不需要权限的页面
SAFE_URL = [
    '/view/',
    '/user/',
    '/notice/',
    '/api/',  # 默认不需登陆，验证接口使用装饰器
]

# 设置管理员团队
MANAGE_TEAM = ['安全']

# 设置网站根地址
WEB_URL = 'http://localhost:8000'

# 设置登录初始路径
LOGIN_URL = '/view/'

# 设置缓存文件路径
TMP_PATH = os.path.join(BASE_DIR, 'tmp')

# 设置登录session有效时间
SESSION_COOKIE_AGE = 60 * 360
# 设置session管理浏览器失效
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# 设置上传路径
MEDIA_ROOT = os.path.join(BASE_DIR, 'files')
MEDIA_API = os.path.join(MEDIA_ROOT, 'api')
MEDIA_URL = "/uploads/"
# 上传报告类型
MEDIA_TYPE = ['rsas', 'web']

# 定义session 键：
# 保存用户权限url列表
# 保存 权限菜单 和所有 菜单
SESSION_PERMISSION_URL_KEY = 'spuk'
SESSION_MENU_KEY = 'smk'
ALL_MENU_KEY = 'amk'
PERMISSION_MENU_KEY = 'pmk'

# 设置邮箱
# 设置邮箱
EMAIL_HOST = 'smtp-mail.outlook.com'  # SMTP地址
EMAIL_PORT = 25  # SMTP端口
EMAIL_HOST_USER = 'xxxx@xxx.com'  # 我自己的邮箱
EMAIL_HOST_PASSWORD = 'password3'  # 我的邮箱密码
EMAIL_SUBJECT_PREFIX = u'[SeMF]'  # 为邮件Subject-line前缀,默认是'[django]'
EMAIL_USE_TLS = True  # 与SMTP服务器通信时，是否启动TLS链接(安全链接)。默认是false
# 管理员站点
SERVER_EMAIL = 'lintechao@yingzi.com'
DEFAULT_FROM_EMAIL = '安全管控平台<Se@outlook.com>'

# 设置队列存储
BROKER_URL = 'amqp://semf:1qaz@WSX@172.19.130.20/semf'  # 设置与rabbitmq一致
# BROKER_URL = 'amqp://172.19.130.20/semf'
CELERY_ACCEPT_CONTENT = ['pickle', 'json', 'msgpack', 'yaml']

# Application definition

INSTALLED_APPS = [
    "simpleui",  # admin后台UI库
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'RBAC',
    'SeMFSetting',
    'NoticeManage',
    'AssetManage',
    'VulnManage',
    'ChartManage',
    'ArticleManage',
    'MappedManage',
    'TaskManage',
    'API',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'RBAC.middleware.rbac.RbacMiddleware',
]

ROOT_URLCONF = 'SeMF.urls'

# 设置静态模板文件路径
TEMPLATE_PATH = os.path.join(BASE_DIR, 'templates')
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [TEMPLATE_PATH],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'SeMF.wsgi.application'

# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases
#
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
#     }
# }

# 设置mysql数据配置信息
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'SeMF',
        'USER': 'root',
        'PASSWORD': '1qaz@WSX',
        'HOST': '172.19.130.20',
        # 'NAME': 'defectdojo',
        # 'USER': 'defectdojo',
        # 'PASSWORD': 'l8f3JJOhFor',
        # 'HOST': '172.18.10.36',
        'PORT': '3306',
        'OPTIONS': {
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES' ",
            'charset': 'utf8', }
    }
}

# 设置redis配置信息
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://172.19.130.20:6379",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "CONNECTION_POOL_KWARGS": {"max_connections": 100},
            "PASSWORD": "1qaz@WSX",
            "DECODE_RESPONSES": True
        }
    },
}
REDIS_TIMEOUT = 7 * 24 * 60 * 60
CUBES_REDIS_TIMEOUT = 1 * 50 * 60
NEVER_REDIS_TIMEOUT = 365 * 24 * 60 * 60

# LDAP 认证
LDAP_SERVER_POOL = ["corp.yingzi.com:389"]
ADMIN_DN = "yz_semf"
ADMIN_PASSWORD = "9ik44DENWa8"
SEARCH_BASE = "ou=corp,dc=corp,dc=yingzi,dc=com"

# 钉钉H5微应用
AGENT_ID = "825883923"
APP_KEY = 'dingkpdsu0ojcv1dvsqw'
APP_SECRET = 'd-RnJoghM9MDULNobwsl4j64DWV5-_xAMzk8RrrWAABsYGg8Saj9ZVC4VctoC4_Y'

# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/2.0/topics/i18n/
LANGUAGE_CODE = 'zh-Hans'

TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

USE_TZ = False

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'collectstatic')
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, "static"),
)

# 指定simple ui 从本地加载静态文件
SIMPLEUI_STATIC_OFFLINE = True
# 不开启分析提交
SIMPLEUI_ANALYSIS = False
