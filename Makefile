MODULES = jailed
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = pokemongo
DISPLAY_NAME = mitm.login
BUNDLE_ID = com.niico.pokemongo.login

pokemongo_FILES = Tweak.xm
pokemongo_IPA = pokemongo.v0.57.4.ipa

pokemongo_FRAMEWORKS=QuartzCore Security CFNetwork
pokemongo_USE_FISHHOOK=1
pokemongo_USE_FLEX=1
# pokemongo_INJECT_DYLIBS=FridaGadget.dylib

include $(THEOS_MAKE_PATH)/tweak.mk
