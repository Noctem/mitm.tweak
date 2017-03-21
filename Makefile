include $(THEOS)/makefiles/common.mk

TARGET = iphone:clang:9.0:9.0
TARGET_IPHONEOS_DEPLOYMENT_VERSION = 9.0
THEOS_TARGET_IPHONEOS_DEPLOYMENT_VERSION = 9.0
TARGET_VERSION = 9.0
ARCHS = arm64


TWEAK_NAME = mitm
DISPLAY_NAME = mitm
BUNDLE_ID = com.niico.mitm

mitm_FILES = Tweak.xm

mitm_FRAMEWORKS=QuartzCore Security CFNetwork
mitm_USE_FLEX=1

include $(THEOS)/makefiles/tweak.mk
include $(THEOS)/makefiles/aggregate.mk
