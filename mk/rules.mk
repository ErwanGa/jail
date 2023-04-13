##############################################################################
#
# file: rules.mk
#
# Copyright(C) 2021.
#
# Author(s):
#    Erwan GAUTRON
#
# generic rules for makefiles
##############################################################################
ifeq ("$(V)", "1")
Q:=
else
Q:=@
endif



CD:=cd
CP:=cp
MKDIR:=mkdir -p
ECHO:=echo
RM:=rm -rf
INSTALL:=install
SHARP:="\#"

COL_BLACK=\x1b[30m
COL_RED:=\x1b[31m
COL_GREEN:=\x1b[32m
COL_YELLOW:=\x1b[33m
COL_BLUE:=\x1b[34m
COL_MANGENTA:=\x1b[35m
COL_CYAN:=\x1b[36m
COL_WHITE:=\x1b[37m
COL_END:=\x1b[0m

myError   = /bin/echo -e "${COL_RED}${SHARP}$1 ${COL_END}"
myHelp  = /bin/echo -e "${COL_GREEN}${SHARP}$1 ${COL_END}"
myTitle = /bin/echo -e "${COL_CYAN}${SHARP}$1 ${COL_END}"
myCpr   = /bin/echo -e "$1" >> $2

###############################################################
#  BUILD C
###############################################################
CFLAGS:= -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Wformat-security -Wdate-time -Wno-unused-parameter

ifeq ("$(FA)", "1")
CFLAGS+= -fanalyzer
endif

LDFLAGS:=

DBG?=0

############################
# OPT and DEBUG
###########################
ifeq ($(DBG), 0)
CFLAGS+= -Os -fPIE
LDFLAGS+=-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -pie
else
CFLAGS+= -O1 -g -DDEBUG=$(DBG)
endif

#############################
#
############################
DEF_RULES:=1
