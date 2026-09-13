################################################################################
#
# apscream-open
#
################################################################################

APSCREAM_OPEN_VERSION = 1.0
APSCREAM_OPEN_SITE = $(BR2_EXTERNAL_ext_tree_PATH)/package/apscream-open
APSCREAM_OPEN_SITE_METHOD = local
APSCREAM_OPEN_DEPENDENCIES = alsa-lib

define APSCREAM_OPEN_BUILD_CMDS
$(TARGET_CC) $(TARGET_CFLAGS) \
-mcpu=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard \
-ffast-math -fomit-frame-pointer \
-o $(@D)/apscream-open $(@D)/apscream_open.c \
$(TARGET_LDFLAGS) -lasound -lpthread
endef

define APSCREAM_OPEN_INSTALL_TARGET_CMDS
$(INSTALL) -D -m 0755 $(@D)/apscream-open $(TARGET_DIR)/usr/bin/apscream-open
endef

$(eval $(generic-package))
