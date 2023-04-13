##############################################################################
#
# file: help.mk
#
# Copyright(C) 2021
#
# Author(s):
#    Erwan GAUTRON
#
##############################################################################

help:
	$(Q)$(call myTitle,"Help for ${pkg-name} Makefile")
	$(Q)$(call myHelp, "make tgt  \\t- build a target like subtree")
	$(Q)$(call myHelp, "make clean\\t- remove all derivates")


