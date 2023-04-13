##############################################################################
#
# file: Makefile
#
# Copyright(C)
#
# Author(s):
#
##############################################################################
PREFIX?=


tgt: Makefile
tgt: $(bdir)/$(pkg-name)


################################################################
#  C part
################################################################
CROSS_COMPILE?=
CC=$(CROSS_COMPILE)gcc
STRIP=$(CROSS_COMPILE)strip
CFLAGS+=-Iinc -I$(PREFIX)/usr/include/libxml2
LDFLAGS+=-lcap -lcap-ng -lxml2 -lexpat -lrt -pthread



src-files:=$(wildcard  src/*.c)
obj-files:=$(subst src, $(bdir),$(src-files:.c=.o))
dep-files:=$(subst src, $(bdir),$(src-files:.c=.d))
-include $(dep-files)

ifneq ($(PREFIX),)
ifeq ($(PREFIX_ETC),)
PREFIX_ETC=$(PREFIX)
endif
endif


$(bdir)/%.o: src/%.c
	$(Q)$(call myTitle, "[CC] $(@F) ")
	$(Q)$(MKDIR) $(@D)
	$(Q)$(CC) -MD $(CFLAGS) -c $< -o $@

$(bdir)/$(pkg-name): $(obj-files)
	$(Q)$(call myTitle, "[LD] $(@F) ")
	$(Q)$(MKDIR) $(@D)
	$(Q)$(CC) -o $@ $^ $(LDFLAGS)


install: all
	$(MKDIR) $(PREFIX)/bin
	$(MKDIR) $(PREFIX_ETC)/etc
	$(INSTALL) -m 755 $(bdir)/$(pkg-name) $(PREFIX)/bin
	$(INSTALL) -m 644 $(cdir)/configs/jail.dtd $(PREFIX_ETC)/etc

################################################################
#  Clean
################################################################
clean:
	$(Q)$(call myTitle, "clean and remove build directory")
	$(Q)if [ -e $(bdir) ]; then \
		$(RM) -rf $(bdir);\
	fi

