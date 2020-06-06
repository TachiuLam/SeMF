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
        encoded_jwt = jwt.encode({'username': user, 'site': WEB_URL}, SECRET_KEY,
                                 algorithm=ALGORITHM)
        return 'Token ' + bytes.decode(encoded_jwt)

    @staticmethod
    def decode_jwt(token):
        """解码jwt"""
        try:
            b_token = token.split('Token ')[1]
            # print(b_token)
            decode_jwt = jwt.decode(b_token, SECRET_KEY, algorithms=ALGORITHM)
        except Exception as error:
            # print(error)
            return {'error': error}

        return {'user': decode_jwt.get('username')}


if __name__ == '__main__':
    u = 'root'
    r = JWT.generate_jwt(u)
    print(r)
    print(type(r))
    # r= r+b'kjahkhdkashd'
    d = JWT.decode_jwt(r)
    print(d)
