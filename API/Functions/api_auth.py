# -*- coding: utf-8 -*-
# tachiu lam
# techaolin@gmail.com
# 2020/6/6 2:59 下午
# PyCharm
from SeMF.settings import SECRET_KEY, WEB_URL, ALGORITHM
import jwt


class JWT:

    @staticmethod
    def generate_jwt(user):
        """生成jwt"""
        encoded_jwt = jwt.encode({'username': str(user), 'site': WEB_URL}, SECRET_KEY,
                                 algorithm=ALGORITHM)
        return 'Token ' + bytes.decode(encoded_jwt)

    @staticmethod
    def decode_jwt(token):
        """解码jwt"""
        try:
            b_token = token.split('Token ')[1]
            # print(b_token)
            decode_jwt = jwt.decode(b_token, SECRET_KEY, algorithms=ALGORITHM)
            user = decode_jwt.get('username')
            return {'user': user}
            # if User.objects.filter(username=user).first():
            #     return {'result': True}
        except Exception as error:
            print(error)
            pass
        return {'user': False}

        # return {'user': decode_jwt.get('username')}

