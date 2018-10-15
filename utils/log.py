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
            print(word)
            infob = str.encode(word)
            fd.send(infob)
        else:
            msg = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S  ") + word
            fd.write(msg)

    @staticmethod
    def log(word, fd):
        Log._print("%s" % word, fd)

    @staticmethod
    def info(word, fd):
        Log._print("%s" % color.blue(word), fd)

    @staticmethod
    def command(word, fd):
        Log._print("%s" % color.cyan(word), fd)

    @staticmethod
    def warning(word, fd):
        Log._print("%s" % color.yellow(word), fd)

    @staticmethod
    def error(word, fd):
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

