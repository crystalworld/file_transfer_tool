import socket
import hashlib
import json
import re
import os
import sys

conf = json.load(open("client_conf.json", encoding = "utf-8"))
# print(conf)
server_ip = conf["ip地址"]
server_port = conf["端口号"]
# print(server_ip, server_port)
sock = socket.socket() # 创建套接字
# sock.bind(("0.0.0.0", 9876)) # 绑定ip和端口号
sock.connect((server_ip, server_port)) # 请求连接目标服务器

def get_passwd_md5(passwd):
    m = hashlib.md5()
    m.update(passwd.encode())
    return m.hexdigest().upper()


def get_file_md5(file_path):
    m = hashlib.md5()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(1024)
            if len(data) == 0:
                break
            m.update(data)
    return m.hexdigest().upper()


def user_check(uname):
    if not re.match("^[a-zA-Z0-9_]{6,15}$", uname):
        return 2 # 用户名不合法
    req = {"op":3,"args":{"uname":uname}}
    req = json.dumps(req).encode()
    data_len = "{:<15}".format(len(req)).encode()
    sock.send(data_len)
    sock.send(req)

    req_data = sock.recv(15).decode().rstrip()
    # print(len(req_data))
    msg = sock.recv(int(req_data)).decode()
    msg = json.loads(msg)
    print(msg)

    if msg["error_code"] == 0:
        return 0 # 用户名不存在
    else:
        return 1 # 用户名已存在

   
def sock_recv_file():
    while True:
        file_path = sock.recv(300).decode().rstrip()
        if file_path == '':
            break
        file_size = sock.recv(15).decode().rstrip()
        if len(file_size) == 0:
            break
        file_size = int(file_size)

        file_md5 = sock.recv(32).decode()
        if len(file_md5) == 0:
            break

        # 如果为空文件夹
        if file_size == -1:
            print("成功接收空文件%s" % file_path)
            os.makedirs(file_path, exist_ok=True)
            continue
        try:    
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
        except:
            pass

        print("\n正在接收文件 %s，请稍后......" % file_path)

        f = open(file_path, "wb")

        recv_size = 0
        recv_old_load = 0
        while recv_size < file_size:
            file_data = sock.recv(file_size - recv_size)
            if len(file_data) == 0:
                break
            f.write(file_data)
            recv_size += len(file_data)
            recv_new_load = int(recv_size *100 / file_size)
            if recv_new_load > recv_old_load:
                print(".....%s%%....." % recv_new_load)
            recv_old_load = recv_new_load
        f.close()
                                                    
        recv_file_md5 = get_file_md5(file_path)

        if recv_file_md5 == file_md5:
            print("\n成功接收文件%s!" % file_path)
        else:
            print("\n接收文件%s失败（MD5校验不通过）" % file_path)
            break

    sock.close()


def reg_check(uname, passwd, phone, email):
    passwd = get_passwd_md5(passwd)
    req = {"op":2,"args":{"uname":uname,"passwd":passwd,"phone":phone,"email":email}}
    print(req)
    req = json.dumps(req).encode()
    data_len = "{:<15}".format(len(req)).encode()
    # print(type(data_len))
    sock.send(data_len)
    sock.send(req)

    req_data = sock.recv(15).decode().rstrip()
    print(len(req_data))
    msg = sock.recv(int(req_data)).decode()
    msg = json.loads(msg)
    print(msg)
    if msg["error_code"] == 0:
        return 0 # 注册成功
    else:
        return 1 # 注册失败


def login_check(uname, passwd):
    passwd = get_passwd_md5(passwd)
    req = {"op":1,"args":{"uname":uname,"passwd":passwd}}
    # print(req)
    req = json.dumps(req).encode()
    data_len = "{:<15}".format(len(req)).encode()
    # print(type(data_len))
    sock.send(data_len)
    sock.send(req)

    req_data = sock.recv(15).decode().rstrip()
    print(len(req_data))
    msg = sock.recv(int(req_data)).decode()
    msg = json.loads(msg)
    print(msg)
    if msg["error_code"] == 0:
        return 0 # 登录成功
    else:
        return 1 # 登陆失败


# user_check("shuijing")
# reg_check("shuijing", "135468", "15489756324", "shuijing@shss.online")
# print("注册成功！")


if login_check("shuijing", "135468") == 0:
    sock_recv_file()