from django.test import TestCase
from SeMF.redis import Cache
from decimal import *

# Create your tests here.

# key = 'lintechao'
# Cache.set_value('value_test', key=key)
# value = Cache.get_value(key=key)
# print(value)
username_l = []
username_list = ['林特超']
vuln_id = '222020091941437'

u = eval(str(['林特超', '李晓林']))
print(u, type(u))
username_l.extend(username_list)
username_l.extend(u)
# 列表去重
username_l = list(set(username_l))
print(username_l)
a = '1'
with open('./log.txt', 'wb') as f:
    f.write((a+str(username_l)).encode())
print(float(0.1+0.2))
print(Decimal('0.1'+'0.2'))
