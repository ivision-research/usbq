# -*- coding: utf-8 -*-
import math


def ls2hs_interval(interval):
    """ Fix interval of EndpointDescriptors
    Board is acting as a High speed device, so bInterval is interpreted
    as a polling rate equal to (bInterval-1) units with units equat to 125µs.
    Value is then changed to match behavior of a low speed device
    """
    return math.log(interval * 8, 2) + 1
