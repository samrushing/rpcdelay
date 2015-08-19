# -*- Mode: Python -*-

from distutils.core import setup

setup (
    name             = 'rpcdelay',
    description      = 'measure rpc round-trip times between two hosts',
    author           = "Sam Rushing",
    packages         = ['rpcdelay'],
    scripts          = ['scripts/rpcdelay'],
)
