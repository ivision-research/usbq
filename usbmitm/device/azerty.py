#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

KEY_CTRL_LEFT   =  0x01
KEY_CTRL_RIGHT  =  0x10
KEY_CTRL = (KEY_CTRL_LEFT | KEY_CTRL_RIGHT)

KEY_SHIFT_LEFT  =  0x02
KEY_SHIFT_RIGHT =  0x20
KEY_SHIFT = (KEY_SHIFT_LEFT | KEY_SHIFT_RIGHT)

KEY_ALT         =  0x04
KEY_ALTGR       =  0x40

KEY_SUPER_LEFT  =  0x08
KEY_SUPER_RIGHT =  0x80
KEY_SUPER = (KEY_SUPER_LEFT | KEY_SUPER_RIGHT)


keyMap = {
        "none" : {
                "{ESC}":  0x29, "{F1}":  0x3a, "{F2}" :  0x3b, "{F3}":       0x3c,
                "{F4}":   0x3d, "{F5}":  0x3e, "{F6}" :  0x3f, "{F7}":       0x40,
                "{F8}":   0x41, "{F9}":  0x42, "{F10}":  0x43, "{F11}":      0x44,
                "{F12}":  0x45, "²":     0x35, "&" :     0x1e, "é":          0x1f,
                "\"":     0x20, "'":     0x21, "(":      0x22, "-":          0x23,
                "è":      0x24, "_":     0x25, "ç":      0x26, "à":          0x27,
                ")":      0x2d, "=":     0x2e, "a":      0x14, "z":          0x1a,
                "e":      0x08, "r":     0x15, "t":      0x17, "y":          0x1c,
                "u":      0x18, "i":     0x0c, "o":      0x12, "p":          0x13,
                "q":      0x04, "s":     0x16, "d":      0x07, "f":          0x09,
                "g":      0x0a, "h":     0x0b, "j":      0x0d, "k":          0x0e,
                "l":      0x0f, "m":     0x33, "w":      0x1d, "x":          0x1b,
                "c":      0x06, "v":     0x19, "b":      0x05, "n":          0x11,
                "\t":     0x2b, "^":     0x2f, "$":      0x30, "\n":         0x28,
                "ù":      0x34, "*":     0x32, "<":      0x64, ",":          0x10,
                ";":      0x36, ":":     0x37, "!":      0x38, "{UP}":       0x52,
                "{LEFT}": 0x50, "{DOWN}":0x51, "{RIGHT}":0x4f, "{BACKSPACE}":0x2a,
                " ":      0x2c, "{SUPR}":0x4c, "{TAB}"  :0x2b,
        },
        "shift" : {
                "~":0x35,                "1":0x1e,                "2":0x1f,                "3":0x20,
                "4":0x21,                "5":0x22,                "6":0x23,                "7":0x24,
                "8":0x25,                "9":0x26,                "0":0x27,                "°":0x2d,
                "+":0x2e,                "A":0x14,                "Z":0x1a,                "E":0x08,
                "R":0x15,                "T":0x17,                "Y":0x1c,                "U":0x18,
                "I":0x0c,                "O":0x12,                "P":0x13,                "Q":0x04,
                "S":0x16,                "D":0x07,                "F":0x09,                "G":0x0a,
                "H":0x0b,                "J":0x0d,                "K":0x0e,                "L":0x0f,
                "M":0x33,                "W":0x1d,                "X":0x1b,                "C":0x06,
                "V":0x19,                "B":0x05,                "N":0x11,                "¨":0x2f,
                "£":0x30,                "%":0x34,                "%":0x34,                "µ":0x64,
                "?":0x10,                ".":0x36,                "/":0x37,                "§":0x38
        },
        "altgr" : {
                "#":0x20,                "{": 0x21,               "[":0x22,                "|":0x23,
                "`":0x24,                "\\":0x25,               "@":0x27,                "]":0x2d,
                "}":0x2e
        }
}

invkeyMap = {
    "none" : {v: k for k, v in keyMap["none"].items()},
    "shift": {v: k for k, v in keyMap["shift"].items()},
    "altgr": {v: k for k, v in keyMap["altgr"].items()},
}

_modifier = {
    "none": 0,
    "shift":KEY_SHIFT_LEFT,
    "altgr":KEY_ALTGR
}


def get_scan_code(char):
    for mod in keyMap.keys():
        if char in keyMap[mod]:
           return "%c\x00%c\x00\x00\x00\x00\x00" % (chr(_modifier[mod]),chr(keyMap[mod][char]))

def get_modifier(b):
    s = []
    if b&KEY_CTRL_LEFT != 0:
        s.append("[CTRL_LEFT]")
    if b&KEY_CTRL_RIGHT != 0:
        s.append("[CTRL_RIGHT]")
    if b&KEY_SHIFT_LEFT != 0:
        s.append("[SHIFT_LEFT]")
    if b&KEY_SHIFT_RIGHT != 0:
        s.append("[SHIFT_RIGHT]")
    if b&KEY_ALT != 0:
        s.append("[ALT]")
    if b&KEY_ALTGR != 0:
        s.append("[ALTGR]")
    if b&KEY_SUPER_RIGHT != 0:
        s.append("[SUPER_RIGHT]")
    if b&KEY_SUPER_LEFT != 0:
        s.append("[SUPER_LEFT]")
    return "".join(s)

def get_char(scancode):
    s = []
    mod = ord(scancode[0])
    val = ord(scancode[2])
    try:
        if mod & KEY_SHIFT != 0:
            return invkeyMap["shift"][val]
        elif mod & KEY_ALTGR != 0:
            return invkeyMap["altgr"][val]
        else:
            return "%s%s" % (get_modifier(mod),invkeyMap["none"].get(val,"ukn%r" % (val,)))
    except KeyError:
        return "%s%s" % (get_modifier(mod),invkeyMap["none"].get(val,"ukn%r" % (val,)))


if __name__ == "__main__":
    print get_scan_code(sys.argv[1]).encode("hex")
