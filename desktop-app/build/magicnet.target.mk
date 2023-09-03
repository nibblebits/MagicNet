# This file is generated by gyp; do not edit.

TOOLSET := target
TARGET := magicnet
DEFS_Debug := \
	'-DNODE_GYP_MODULE_NAME=magicnet' \
	'-DUSING_UV_SHARED=1' \
	'-DUSING_V8_SHARED=1' \
	'-DV8_DEPRECATION_WARNINGS=1' \
	'-DV8_DEPRECATION_WARNINGS' \
	'-DV8_IMMINENT_DEPRECATION_WARNINGS' \
	'-D_GLIBCXX_USE_CXX11_ABI=1' \
	'-DELECTRON_ENSURE_CONFIG_GYPI' \
	'-D_LARGEFILE_SOURCE' \
	'-D_FILE_OFFSET_BITS=64' \
	'-DUSING_ELECTRON_CONFIG_GYPI' \
	'-DV8_COMPRESS_POINTERS' \
	'-DV8_COMPRESS_POINTERS_IN_SHARED_CAGE' \
	'-DV8_ENABLE_SANDBOX' \
	'-DV8_31BIT_SMIS_ON_64BIT_ARCH' \
	'-D__STDC_FORMAT_MACROS' \
	'-DOPENSSL_NO_PINSHARED' \
	'-DOPENSSL_THREADS' \
	'-DOPENSSL_NO_ASM' \
	'-DBUILDING_NODE_EXTENSION' \
	'-DDEBUG' \
	'-D_DEBUG' \
	'-DV8_ENABLE_CHECKS'

# Flags passed to all source files.
CFLAGS_Debug := \
	-fPIC \
	-pthread \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-m64 \
	-g \
	-fPIC \
	-fpermissive \
	-g \
	-O0

# Flags passed to only C files.
CFLAGS_C_Debug :=

# Flags passed to only C++ files.
CFLAGS_CC_Debug := \
	-fno-rtti \
	-std=gnu++17

INCS_Debug := \
	-I/home/daniel/.electron-gyp/25.3.2/include/node \
	-I/home/daniel/.electron-gyp/25.3.2/src \
	-I/home/daniel/.electron-gyp/25.3.2/deps/openssl/config \
	-I/home/daniel/.electron-gyp/25.3.2/deps/openssl/openssl/include \
	-I/home/daniel/.electron-gyp/25.3.2/deps/uv/include \
	-I/home/daniel/.electron-gyp/25.3.2/deps/zlib \
	-I/home/daniel/.electron-gyp/25.3.2/deps/v8/include \
	-I$(srcdir)/node_modules/nan \
	-I$(srcdir)/../lib/include

DEFS_Release := \
	'-DNODE_GYP_MODULE_NAME=magicnet' \
	'-DUSING_UV_SHARED=1' \
	'-DUSING_V8_SHARED=1' \
	'-DV8_DEPRECATION_WARNINGS=1' \
	'-DV8_DEPRECATION_WARNINGS' \
	'-DV8_IMMINENT_DEPRECATION_WARNINGS' \
	'-D_GLIBCXX_USE_CXX11_ABI=1' \
	'-DELECTRON_ENSURE_CONFIG_GYPI' \
	'-D_LARGEFILE_SOURCE' \
	'-D_FILE_OFFSET_BITS=64' \
	'-DUSING_ELECTRON_CONFIG_GYPI' \
	'-DV8_COMPRESS_POINTERS' \
	'-DV8_COMPRESS_POINTERS_IN_SHARED_CAGE' \
	'-DV8_ENABLE_SANDBOX' \
	'-DV8_31BIT_SMIS_ON_64BIT_ARCH' \
	'-D__STDC_FORMAT_MACROS' \
	'-DOPENSSL_NO_PINSHARED' \
	'-DOPENSSL_THREADS' \
	'-DOPENSSL_NO_ASM' \
	'-DBUILDING_NODE_EXTENSION'

# Flags passed to all source files.
CFLAGS_Release := \
	-fPIC \
	-pthread \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-m64 \
	-g \
	-fPIC \
	-fpermissive \
	-O3 \
	-fno-omit-frame-pointer

# Flags passed to only C files.
CFLAGS_C_Release :=

# Flags passed to only C++ files.
CFLAGS_CC_Release := \
	-fno-rtti \
	-std=gnu++17

INCS_Release := \
	-I/home/daniel/.electron-gyp/25.3.2/include/node \
	-I/home/daniel/.electron-gyp/25.3.2/src \
	-I/home/daniel/.electron-gyp/25.3.2/deps/openssl/config \
	-I/home/daniel/.electron-gyp/25.3.2/deps/openssl/openssl/include \
	-I/home/daniel/.electron-gyp/25.3.2/deps/uv/include \
	-I/home/daniel/.electron-gyp/25.3.2/deps/zlib \
	-I/home/daniel/.electron-gyp/25.3.2/deps/v8/include \
	-I$(srcdir)/node_modules/nan \
	-I$(srcdir)/../lib/include

OBJS := \
	$(obj).target/$(TARGET)/src/cpp/magicnetext.o

# Add to the list of files we specially track dependencies for.
all_deps += $(OBJS)

# CFLAGS et al overrides must be target-local.
# See "Target-specific Variable Values" in the GNU Make manual.
$(OBJS): TOOLSET := $(TOOLSET)
$(OBJS): GYP_CFLAGS := $(DEFS_$(BUILDTYPE)) $(INCS_$(BUILDTYPE))  $(CFLAGS_$(BUILDTYPE)) $(CFLAGS_C_$(BUILDTYPE))
$(OBJS): GYP_CXXFLAGS := $(DEFS_$(BUILDTYPE)) $(INCS_$(BUILDTYPE))  $(CFLAGS_$(BUILDTYPE)) $(CFLAGS_CC_$(BUILDTYPE))

# Suffix rules, putting all outputs into $(obj).

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(srcdir)/%.cpp FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

# Try building from generated source, too.

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(obj).$(TOOLSET)/%.cpp FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

$(obj).$(TOOLSET)/$(TARGET)/%.o: $(obj)/%.cpp FORCE_DO_CMD
	@$(call do_cmd,cxx,1)

# End of this set of suffix rules
### Rules for final target.
LDFLAGS_Debug := \
	-pthread \
	-rdynamic \
	-m64

LDFLAGS_Release := \
	-pthread \
	-rdynamic \
	-m64

LIBS := \
	-L../lib/include -lmagicnet

$(obj).target/magicnet.node: GYP_LDFLAGS := $(LDFLAGS_$(BUILDTYPE))
$(obj).target/magicnet.node: LIBS := $(LIBS)
$(obj).target/magicnet.node: TOOLSET := $(TOOLSET)
$(obj).target/magicnet.node: $(OBJS) FORCE_DO_CMD
	$(call do_cmd,solink_module)

all_deps += $(obj).target/magicnet.node
# Add target alias
.PHONY: magicnet
magicnet: $(builddir)/magicnet.node

# Copy this to the executable output path.
$(builddir)/magicnet.node: TOOLSET := $(TOOLSET)
$(builddir)/magicnet.node: $(obj).target/magicnet.node FORCE_DO_CMD
	$(call do_cmd,copy)

all_deps += $(builddir)/magicnet.node
# Short alias for building this executable.
.PHONY: magicnet.node
magicnet.node: $(obj).target/magicnet.node $(builddir)/magicnet.node

# Add executable to "all" target.
.PHONY: all
all: $(builddir)/magicnet.node
