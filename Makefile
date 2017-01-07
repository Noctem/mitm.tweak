MODULES = jailed
include $(THEOS)/makefiles/common.mk

#TARGET_IPHONEOS_DEPLOYMENT_VERSION=8.0

TWEAK_NAME = pokemongo
DISPLAY_NAME = mitm
BUNDLE_ID = com.nico.pokemongo

pokemongo_FILES = Tweak.xm
pokemongo_IPA = pokemongo.v0.51.2.ipa
# pokemongo_IPA = /Users/nico/Downloads/Poke_Go++1.21.1_1.6r-19.ipa

pokemongo_FRAMEWORKS=QuartzCore

# pokemongo_INJECT_DYLIBS=FridaGadget.dylib

include $(THEOS_MAKE_PATH)/tweak.mk
