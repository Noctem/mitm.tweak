MODULES = jailed
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = pokemongo
DISPLAY_NAME = mitm
BUNDLE_ID = com.niico.pokemongo

pokemongo_FILES = Tweak.xm
pokemongo_IPA = pokemongo.v0.51.2.ipa

pokemongo_FRAMEWORKS=QuartzCore

include $(THEOS_MAKE_PATH)/tweak.mk
