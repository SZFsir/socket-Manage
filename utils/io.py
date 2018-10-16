#! /usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "JrXnm"
# Date: 18-10-16
import datetime
from .log import Log


# 所有接到的消息log
def save_info(path, buf, interactive_user):

    try:
        with open(path, 'wb') as f:
            f.write(buf)
    except FileNotFoundError:
        msg = '\n./Log/ directory is not exist. Can not write file.\n'
        if interactive_user:
            Log.error(msg, interactive_user)


# 连接log
def log_save(fd, interactive_user):
    shost, sport = fd.getpeername()
    msg = shost + ' ' + str(sport) + ' is connect\n'
    t = datetime.datetime.now().strftime("%Y-%m-%d")
    path = './log/' + t + '.log'
    try:
        with open(path, 'a') as f:
            Log.log(msg, f)
    except FileNotFoundError:
        msg = '\n./Log/ directory is not exist. Can not write file.\n'
        if interactive_user:
            Log.error(msg, interactive_user)


# 服务器运行过程log
def server_log(msg):
    path = './log/severlog.log'
    try:
        with open(path, 'a') as f:
            Log.log(msg, f)
    except FileNotFoundError:
        print('\n./Log/ directory is not exist. Can not write file.\n')
