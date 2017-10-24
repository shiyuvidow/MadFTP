# -*- coding: utf-8 -*-
import random
import os
from hashlib import sha256
from hmac import HMAC


# 加入随机salt的哈希算法，不可还原明文
def set_password(raw_password, salt=None):
    if salt is None:
        salt = sha256(str(random.random())).hexdigest()[-8:]
    if isinstance(raw_password, unicode):
        raw_password = raw_password.encode('utf-8')
    password = HMAC(salt, raw_password, sha256).hexdigest()
    return '%s$%s' % (salt, password)


def check_password(raw_password, enc_password):
    salt = enc_password.split('$')[0]
    return enc_password == set_password(raw_password, salt)


def get_quotation(path):
    size = 0L
    for root, dirs, files in os.walk(path, True):
        size += sum([os.path.getsize(os.path.join(root, name)) for name in files])
    return size
