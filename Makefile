PLUGIN_NAME	=	v8glue
CXXFILES	=	v8glue.cxx coverage.cc
LDFLAGS		=	-L. -lfuzztarget283779-35 -rpath '$$ORIGIN'
#-lfuzztarget283779-4
#-lfuzztarget283779-22
#-lfzbz-libcrypto

CXXFLAGS 	= 	-fsanitize=address


include /home/cbrooks/work/bex//plugin.mk

