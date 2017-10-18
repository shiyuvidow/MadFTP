#coding:utf-8

from optparse import OptionParser
import SocketServer
from core.ftp_server import FTPHandler
from conf import settings


class ArgvHandler(object):
    def __init__(self):
        # 读取输入参数
        self.parser = OptionParser()
        (options, args) = self.parser.parse_args()
        self.verify_args(options, args)

    def verify_args(self, options, args):
        if hasattr(self, args[0]):
            func = getattr(self, args[0])
            func()
        else:
            self.parser.print_help()

    def start(self):
        print("---start---")
        # 多线程
        server = SocketServer.ThreadingTCPServer((settings.HOST, settings.PORT), FTPHandler)
        # 监听
        server.serve_forever()
