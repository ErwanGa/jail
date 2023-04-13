##############################################################################
#
# file: Makefile
#
# Copyright(C) 2021
#
# Author(s):
#    Erwan GAUTRON
#
##############################################################################
cdir:=$(PWD)
bdir:=$(cdir)/_build
pkg-name:=jail

all:tgt

#Include some generic definitions
include mk/rules.mk

#include help target definition
include mk/help.mk

#add tgt and clean target
include mk/tgt.mk


PHONY: tgt clean _build

