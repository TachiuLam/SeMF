from django.test import TestCase
from SeMF.redis import Cache
# Create your tests here.

key = 'lintechao'
value = Cache.get_value(key=key).get('name_zh')
print(value)