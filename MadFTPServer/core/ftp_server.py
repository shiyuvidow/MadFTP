# -*- coding: utf-8 -*-

import SocketServer
import os
import json
import ConfigParser
import hashlib
from conf import settings
from core.common import check_password
import progressbar
import shutil

STATUS_CODE = {
    200: "Info",
    250: "Invalid cmd format",
    251: "Invalid cmd",
    252: "Invalid auth data",
    253: "Wrong username or password",
    254: "Passed authentication",
    255: "Filename doesn't provided",
    256: "File doesn't exist on server",
    257: "ready to send file",
    258: "md5 verification",
    259: "ready to receive file",
    260: "pwd message",
    261: "mkdir success",
    262: "dir already exists",
    263: "cd success",
    264: "dir not exists",
    265: "can not cd  upper dir",
    266: "ls success",
    267: "rm success",
    268: "continue to receive file"
}


# FTP类
class FTPHandler(SocketServer.BaseRequestHandler):
    # 连接实例调用的数据处理方法
    def handle(self):
        while True:
            # self.request表连接实例
            self.data = self.request.recv(1024).strip()
            # 数据为空重新接收
            if not self.data:
                break
            # print(self.client_address[0])
            # 解析json数据
            # 先decode后loads
            data = json.loads(self.data.decode('utf-8'))
            action = data.get("action", None)
            # 构造函数名，避免关键字冲突
            # 反射不支持私有方法
            action_func = "_%s" % action
            if action:
                if hasattr(self, action_func):
                    func = getattr(self, action_func)
                    func(**data)
                else:
                    print("invalid cmd")
                    self.send_response(251)
            else:
                print("invalid cmd format")
                self.send_response(250)

    def send_response(self, status_code, data=None):
        """
        统一处理返回客户端数据
        """
        response = {'status_code': status_code, 'status_msg': STATUS_CODE[status_code]}
        if data:
            # 更新数据,字典更新用update
            response.update(data)
        # 先dumps后encode
        print "send: ", response

        self.request.send(json.dumps(response).encode('utf-8'))

    def get_response(self):
        """
        统一处理客户端发送的请求消息，不包括传输数据
        """
        data = self.request.recv(1024)
        # 先decode后loads
        data = json.loads(data.decode('utf-8'))
        print "response: ", data
        return data

    def authenticate(self, username, token=None):
        """
        验证用户合法性，合法返回数据
        """
        config = ConfigParser.ConfigParser()
        config.read(settings.ACCOUNT_DIR)
        if username in config.sections():
            _password = config.get(username, 'Password')
            token = token.encode('utf-8')
            print "token: {}".format(token)
            if check_password(_password, token):
            # if _password == password:
                # 获取相应username的配置信息
                return config.items(username)
            else:
                return
        else:
            return

    def _auth(self, *args, **kwargs):
        username = kwargs.get('username', None)
        # password = kwargs.get('password', None)
        token = kwargs.get('token', None)
        if not username or not token:
            self.send_response(252)
        # 返回格式[('password', '123'), ('quotation', '100')]转换成字典
        userdata = self.authenticate(username, token)
        if userdata:
            self.userdata = dict(userdata)
            self.userdata.update(username=username)
            print("Pass Auth: ", self.userdata)
            self.user_home_dir = "%s/%s" % (settings.USER_HOME, self.userdata.get('username', ''))
            self.send_response(254)
        else:
            self.send_response(253)

    def show_process(self, received_size=0, total=0):
        # 进度条显示
        bar = progressbar.ProgressBar(maxval=total)
        bar.start()
        while received_size < total:
            bar.update(received_size)
            new_size = yield
            received_size += new_size
        bar.finish()

    def _put(self, *args, **kwargs):
        """
        client send file to server
        :return:
        """
        filename = kwargs.get('filename', None)
        filesize = kwargs.get('filesize', 0)
        md5_required = kwargs.get('md5', 0)
        offset = kwargs.get('offset', '')
        dest_dir = self.user_home_dir
        if offset:
            dest_dir += '/' + offset
        # user_home_dir = "%s/%s" % (settings.USER_HOME, self.userdata.get('username', ''))
        file_abs_path = "%s/%s" % (dest_dir, filename)
        ret = os.path.isfile(file_abs_path)
        if not ret:
            print "ready to receive file--"
            self.send_response(259)
            received_size = 0
            file_obj = open(file_abs_path, 'wb')
        else:
            print "continue to receive file--"
            received_size = os.path.getsize(file_abs_path)
            self.send_response(268, data={'recvsize': received_size})
            file_obj = open(file_abs_path, 'ab')
        progress = self.show_process(received_size, filesize)
        progress.next()
        if md5_required:
            md5_obj = hashlib.md5()
            while received_size < filesize:
                data = self.request.recv(4096)
                file_obj.write(data)
                received_size += len(data)
                md5_obj.update(data)
                try:
                    progress.send(len(data))
                except StopIteration as e:
                    pass
            else:
                print("----->file rece done-----")
                file_obj.close()
                md5_val = md5_obj.hexdigest()
                md5_from_server = self.get_response()
                if md5_from_server.get("md5", "") == md5_val:
                    print "file %s md5 match" % filename
        else:
            while received_size < filesize:
                data = self.request.recv(4096)
                file_obj.write(data)
                received_size += len(data)
                try:
                    progress.send(len(data))
                except StopIteration as e:
                    pass
            else:
                print("----->file rece done-----")
                file_obj.close()

    def _get(self,  *args, **kwargs):
        """
        server send file to client
        :return:
        """
        filename = kwargs.get('filename', None)
        if not filename:
            self.send_response(255)
        received_size = kwargs.get("recvsize", None)
        md5_required = kwargs.get('md5', 0)
        dest_dir = self.user_home_dir
        # 如果是从当前目录取文件
        if not filename.startswith('/'):
            # 用户所在位置
            offset = kwargs.get('offset', '')
            if offset:
                dest_dir += '/' + offset
        # 从根目录取文件
        # user_home_dir = "%s/%s" % (settings.USER_HOME, self.userdata.get('username', ''))
        file_abs_path = "%s/%s" % (dest_dir, filename)
        if os.path.isfile(file_abs_path):
            file_size = os.path.getsize(file_abs_path)
            self.send_response(257, data={'filesize': file_size})
            # 强制清空数据缓存，避免粘包问题
            self.get_response()
            file_obj = open(file_abs_path, "rb")
            if received_size:
                print "continue to send file--"
                file_obj.seek(received_size)
            else:
                print "ready to send file--"
            # 根据是否需要MD5分为两种情况，这样写
            # 是为了不在发送的每行做md5检测后update消耗时间
            if md5_required:
                md5_obj = hashlib.md5()
                for line in file_obj:
                    self.request.send(line)
                    md5_obj.update(line)
                else:
                    file_obj.close()
                    md5_val = md5_obj.hexdigest()
                    self.send_response(258, data={'md5': md5_val})
                    print "send file done..."
            else:
                for line in file_obj:
                    self.request.send(line)
                else:
                    file_obj.close()
                    print "send file done..."
        else:
            self.send_response(256)

    def _ls(self,  *args, **kwargs):
        offset = kwargs.get('offset', '')
        dest_dir = '/'.join([self.user_home_dir, offset])
        if os.path.isdir(dest_dir):
            data = ','.join(os.listdir(dest_dir))
            self.send_response(266, data={'ls': data})
        else:
            self.send_response(264)

    def _cd(self,  *args, **kwargs):
        offset = kwargs.get('offset', '')
        filedir = kwargs.get('filedir', '')
        if not filedir.startswith('/'):
            dest_dir = '/'.join([self.user_home_dir, offset])
            filedir_list = filedir.split('/')
            for f in filedir_list:
                if f == '.':
                    dest_dir = dest_dir
                elif f == '..':
                    dest_dir = os.path.dirname(dest_dir)
                    # 已是用户根目录
                    if len(dest_dir) < len(self.user_home_dir):
                        self.send_response(265, data={'offset': offset})
                else:
                    dest_dir += '/' + f
            offset_now = dest_dir.split(self.user_home_dir)[-1].strip('/')
        else:
            dest_dir = '/'.join([self.user_home_dir, filedir])
            offset_now = filedir.strip('/')
        if os.path.exists(dest_dir):
            self.send_response(263, data={'offset': offset_now})
        else:
            self.send_response(264)

    def _pwd(self,  *args, **kwargs):
        offset = kwargs.get('offset', '')
        pwd = '/'
        if offset:
            pwd += offset.strip()
        data = {
            'pwd': pwd
        }
        self.send_response(260, data=data)

    def _mkdir(self,  *args, **kwargs):
        offset = kwargs.get('offset', '')
        filedir = kwargs.get('filedir', '')
        if not filedir.startswith('/'):
            dir_list = [self.user_home_dir, offset, filedir]
            dest_dir = '/'.join(dir_list)
        else:
            dest_dir = self.user_home_dir.rstrip('/') + filedir
        if os.path.exists(dest_dir):
            self.send_response(262)
        else:
            os.makedirs(dest_dir)
            self.send_response(261)

    def _rm(self,  *args, **kwargs):
        offset = kwargs.get('offset', '')
        filedir = kwargs.get('filedir', '')
        if not filedir.startswith('/'):
            dir_list = [self.user_home_dir, offset, filedir]
            dest_dir = '/'.join(dir_list)
        else:
            dest_dir = self.user_home_dir.rstrip('/') + filedir
        if not os.path.exists(dest_dir):
            self.send_response(264)
        else:
            shutil.rmtree(dest_dir)
            self.send_response(267)






