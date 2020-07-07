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
import ldap
from django_auth_ldap.config import LDAPSearch, PosixGroupType

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
SERVER_EMAIL = 'xxxxx'
DEFAULT_FROM_EMAIL = '安全管控平台<Se@outlook.com>'

# 设置队列存储
BROKER_URL = 'amqp://user:psd@xx.xx.xx.xx/vhost'  # 设置与rabbitmq一致
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
CUBES_REDIS_TIMEOUT = 60 * 60
NEVER_REDIS_TIMEOUT = 365 * 24 * 60 * 60

# LDAP 认证
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',  # 配置为先使用LDAP认证，如通过认证则不再使用后面的认证方式
    'django.contrib.auth.backends.ModelBackend',  # 同时打开本地认证，因为下游系统的权限和组关系需要用到
)
base_dn = 'dc=corp,dc=yingzi,dc=com'
AUTH_LDAP_SERVER_URI = 'ldap://corp.yingzi.com:389'
AUTH_LDAP_BIND_DN = 'uid=test04,ou=users,dc=corp,dc=yingzi,dc=com'  # read only ldap user
AUTH_LDAP_BIND_PASSWORD = '1qaz@WSXwaf1'
AUTH_LDAP_USER_SEARCH = LDAPSearch('ou=users,%s' % base_dn, ldap.SCOPE_SUBTREE, "(uid=%(user)s)")
# AUTH_LDAP_ALWAYS_UPDATE_USER = False  # Default is True,是否登录后从ldap同步用户，不进行同步，因为下游的用户表是什么样的不能确定，只能确定它也使用邮箱前缀
# 下游系统不从ldap同步group staff/superuser相关，但需要从ldap验证用户是否离职
# AUTH_LDAP_GROUP_SEARCH = LDAPSearch('ou=corp,dc=corp,dc=yingzi,dc=com', ldap.SCOPE_SUBTREE, "(objectClass=posixGroup)")
# AUTH_LDAP_GROUP_TYPE = PosixGroupType(name_attr="cn")
# AUTH_LDAP_REQUIRE_GROUP = u"cn=员工,ou=Group,dc=ldap,dc=ssotest,dc=net"
# AUTH_LDAP_DENY_GROUP = u"cn=黑名单,ou=Group,dc=ldap,dc=ssotest,dc=net"
# AUTH_LDAP_FIND_GROUP_PERMS = True  # django从ldap的组权限中获取权限,这种方式，django自身不创建组，每次请求都调用ldap，下游子系统，我们并不需要让他同步ldap里的"员工","管理员"这种表，所以不用mirror_groups
# AUTH_LDAP_CACHE_GROUPS = True  # 如打开FIND_GROUP_PERMS后，才生效，对组关系进行缓存，不用每次请求都调用ldap
AUTH_LDAP_GROUP_CACHE_TIMEOUT = 600

AUTH_LDAP_CONNECTION_OPTIONS = {
    ldap.OPT_DEBUG_LEVEL: 1,
    ldap.OPT_REFERRALS: 0,
}
# 当ldap用户登录时，从ldap的用户属性对应写到django的user数据库，键为django的属性，值为ldap用户的属性
AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail"
}

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
