#!/usr/bin/env python
# -*- coding: utf-8 -*-

class InsensitiveDict(dict):
    def __setitem__(self, key, value):
        super(InsensitiveDict, self).__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super(InsensitiveDict, self).__getitem__(key.lower())

    def __contains__(self,key):
        return super(InsensitiveDict, self).__contains__(key.lower())


class Color:
    normal = 7
    black = 0
    red = 160
    green = 28
    yellow = 220
    blue = 12
    purple = 126
    cyan = 45
    grey = 239

    normal = 0
    bold = 1

def colorize(s,color):
    if type(color) is tuple:
        color,modif = color
        return "\033[%dm\x1b[38;5;%dm%s\x1b[0m\033[0m" % (modif,color,s)
    else:
        return "\x1b[38;5;%dm%s\x1b[0m" % (color,s)

if __name__ == "__main__":
    for i in xrange(256):
        print colorize("%05u" % i,i)


