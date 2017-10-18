#coding:utf-8

import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

USER_HOME = "%s/home" % BASE_DIR
LOG_DIR = "%s/log" % BASE_DIR
LOG_LEVEL = "DEBUG"

SALT_VALUE = "12345678"