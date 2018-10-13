#! /usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "JrXnm"
# Date: 18-10-12
import socket
import threading
import sys
from hashlib import md5


MAX_CONNECTION_NUMBER = 16
EXIT_FLAG = False
slaves = {}
interactive_slave = None


def node_hashs(host, port):
    s = "%s:%d" % (host, port)
    h = md5()
    h.update(s.encode('utf-8'))
    return h.hexdigest()


class Salve(object):
    """Salve"""

    def __init__(self, socket_fd):
        self.socket_fd = socket_fd
        self.hostname, self.port = socket_fd.getpeername()
        self.node_hash = node_hashs(self.hostname, self.port)
        self.interactive = False

    def save_salve(self):
        pass

    def getinfo(self):
        return self.hostname, self.port, self.node_hash

    def interactive_shell(self, user_fd):
        self.interactive = True
        t = threading.Thread(target=transfer2user, args=(user_fd, 'interactive_shell'),
                             kwargs={'slave_fd' : self.socket_fd})
        t.start()
        while True:
            if EXIT_FLAG:
                break
            buf = self.socket_fd.recv(2048)
            if buf == b'':
                break
            if buf:
                bufss = str(buf, encoding="utf-8")
                fd_send(user_fd, bufss)
            if not self.interactive:
                break


def print_salve(user_fd):
    global interactive_slave
    for key in slaves.keys():
        info = slaves[key].getinfo()
        sinfo = str(info[0]) + ' ' + str(info[1]) + ' ' + str(info[2]) + ' ' + '\n'
        fd_send(user_fd, sinfo)
        interactive_slave = slaves[key]


def transfer2user(user_fd, mod, **kwargs):
    global interactive_slave
    while True:
        print('get user info')
        if EXIT_FLAG:
            break
        buf = user_fd.recv(2048)
        if buf == b'':
            break
        if buf:
            command = str(buf, encoding="utf-8")
            print(command)
            if mod == 'interactive_shell':
                slave_fd = kwargs['slave_fd']
                fd_send(slave_fd, command)
            if mod == 'Control_Command':
                if command == 's\n':
                    print_salve(user_fd)
                elif command == 'i\n':
                    slave = interactive_slave
                    slave.interactive_shell(user_fd)


def master(port):
    master_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    master_fd.bind(('', port))
    master_fd.listen(MAX_CONNECTION_NUMBER)

    while True:
        if EXIT_FLAG:
            break
        slave_fd, slave_addr = master_fd.accept()
        slave = Salve(slave_fd)
        slave.save_salve()
        slaves[slave.node_hash] = slave

    master_fd.shutdown(socket.SHUT_RDWR)
    master_fd.close()


def user_connect(port):
    server_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_fd.bind(('', port))
    server_fd.listen(5)

    while True:
        if EXIT_FLAG:
            break
        user_fd, user_addr = server_fd.accept()
        t1 = threading.Thread(target=manage, args=(user_fd,))
        t1.start()


def fd_send(fd, message):
    print(message)
    infob = str.encode(message)
    fd.send(infob)


def check_admin(user_fd):
    hint = 'This is JrXnm socket manage, Please send your token.\n'
    for i in range(3):

        fd_send(user_fd, hint)
        buf = user_fd.recv(2048)
        if buf == b'':
            break
        if buf:
            bufss = str(buf, encoding="utf-8")
            if bufss != 'qwerasdf\n':
                hint = 'Authentication failed, Please send again!\n'
                continue
        return True
    return False


def manage(user_fd):
    check_user = check_admin(user_fd)

    if check_user:
        msg = 'You are admin now \n'
        fd_send(user_fd, msg)
    else:
        msg = 'You are not admin, exit now \n'
        fd_send(user_fd, msg)
        user_fd.shutdown(socket.SHUT_RDWR)
        user_fd.close()
    t1 = threading.Thread(target=master, args=(8994,))
    t1.start()
    t = threading.Thread(target=transfer2user, args=(user_fd, 'Control_Command'))
    t.start()
    print('dfgdfgdf')
    fd_send(user_fd, msg)

user_connect(3116)










