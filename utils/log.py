#! /usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "JrXnm"
# Date: 18-10-14

from . import color
import socket
import datetime



class Log():
    @staticmethod
    def _print(word, fd):
        if isinstance(fd, socket.socket):
            server_log(word)
            infob = str.encode(word)
            fd.sendall(infob)
        else:
            try:
                msg = datetime.datetime.now().strftime("[ %Y-%m-%d %H:%M:%S ]  ") + word
                fd.write(msg)
            except:
                msg = datetime.datetime.now().strftime("[ %Y-%m-%d %H:%M:%S ]  ") + 'something wrong ' \
                                                                                    'in save command\n\n'
                fd.write(msg)

    @staticmethod
    def log(word, fd):
        Log._print("%s" % word, fd)

    @staticmethod
    def info(word, fd=None):
        Log._print("%s" % color.blue(word), fd)

    @staticmethod
    def command(word, fd):
        Log._print("%s" % color.cyan(word), fd)

    @staticmethod
    def warning(word, fd=None):
        Log._print("%s" % color.yellow(word), fd)

    @staticmethod
    def error(word, fd=None):
        Log._print("%s" % color.red(word), fd)

    @staticmethod
    def success(word, fd):
        Log._print("%s" % color.purple(word), fd)

    @staticmethod
    def query(word, fd):
        Log._print("%s" % color.underline(word), fd)

    @staticmethod
    def context(context):
        Log._print("%s" % (color.red(context)))


def server_log(msg):
    path = './log/severlog.log'
    try:
        with open(path, 'a') as f:
            Log.log(msg, f)
    except FileNotFoundError:
        print('\n./Log/ directory is not exist. Can not write file.\n')
