from django.test import TestCase
from SeMF.redis import Cache


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
