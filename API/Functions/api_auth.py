# -*- coding: utf-8 -*-
# tachiu lam
# techaolin@gmail.com
# 2020/6/6 2:59 下午
# PyCharm
from SeMF.settings import SECRET_KEY, WEB_URL, ALGORITHM
import jwt
import time


class JWT:

    @staticmethod
    def generate_jwt(user, **kwargs):
        """生成jwt，可自定义传入参数，如 k=2"""
        info = {'username': str(user), 'site': WEB_URL, 'timestamp': time.ctime()}
        for key, value in kwargs.items():
            info[key] = value
        encoded_jwt = jwt.encode(info, SECRET_KEY,
                                 algorithm=ALGORITHM)
        return 'Token ' + bytes.decode(encoded_jwt)

    @staticmethod
    def decode_jwt(token):
        """解码jwt"""
        try:
            b_token = token.split('Token ')[1]
            # print(b_token)
            decode_jwt = jwt.decode(b_token, SECRET_KEY, algorithms=ALGORITHM)
            # user = decode_jwt.get('username')
            # return {'user': user}
            return decode_jwt
        except Exception as error:
            print(error)
            pass
        return False

        # return {'user': decode_jwt.get('username')}

