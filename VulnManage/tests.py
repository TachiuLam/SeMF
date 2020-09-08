from django.test import TestCase
from SeMF.redis import Cache
# Create your tests here.

key = 'lintechao'
Cache.set_value('value_test', key=key)
value = Cache.get_value(key=key)
print(value)