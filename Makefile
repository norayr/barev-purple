ifeq ($(OS),Windows_NT)
  ifeq ($(origin CC),default)
    CC := i686-w64-mingw32-gcc
  endif
else
CC      ?= gcc
endif
SOURCE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
CFLAGS  ?= -g -O2
PYTHON  ?= python3
DBUS ?= $(if $(filter Windows_NT,$(OS)),0,1)
ifeq ($(DBUS),1)
ifeq ($(shell pkg-config --atleast-version=2.54 gio-2.0 && echo yes),)
$(error GIO 2.54 or newer is required; use DBUS=0 to disable the local interface)
endif
DBUS_CFLAGS := $(shell pkg-config --cflags gio-2.0) -DBAREV_DBUS
DBUS_LIBS := $(shell pkg-config --libs gio-2.0)
endif
PIDGIN_UI ?= $(if $(filter Windows_NT,$(OS)),0,$(shell pkg-config --exists pidgin && echo 1 || echo 0))
ifeq ($(PIDGIN_UI),1)
SECURITY_UI_CFLAGS := $(shell pkg-config --cflags pidgin) -DBAREV_PIDGIN_UI -Wno-deprecated-declarations
SECURITY_UI_LIBS := $(shell pkg-config --libs pidgin gmodule-2.0)
endif
WARN    ?= -Wall -Wextra -Wno-unused-parameter
ifeq ($(OS),Windows_NT)
  PICFLAG ?=
  GLIB_ADDITIONAL ?= gobject-2.0
  EXT := dll
  WIN_LIBS ?= -lws2_32 -lnetapi32 -luuid
  PURPLE_ADDITIONAL ?= -IC:/msys64/ucrt64/include
else
  PICFLAG ?= -fPIC
  GLIB_ADDITIONAL ?=
  EXT := so
  WIN_LIBS ?=
  PURPLE_ADDITIONAL ?=
endif

BAREV_BUILD_ID ?= $(shell git -C "$(SOURCE_DIR)" describe --tags --always --dirty 2>/dev/null || \
	dpkg-parsechangelog -l"$(SOURCE_DIR)/debian/changelog" -SVersion 2>/dev/null || \
	cat "$(SOURCE_DIR)/VERSION" 2>/dev/null || printf unknown)

# Where to install the plugin:
PLUGIN_DIR := $(shell pkg-config --variable=plugindir purple)

# Where to install icons:
DATADIR := $(shell pkg-config --variable=datadir purple)
ICON_DIR := $(DATADIR)/pixmaps/pidgin/protocols
ICON_STYLE ?= black
ICON_PNG := barev_$(ICON_STYLE).png
ICON_SVG := $(if $(filter white,$(ICON_STYLE)),barev_white.svg,barev.svg)

# Static Barev protocol metadata consumed by Mission Control before Haze starts.
TELEPATHY_MANAGER_DIR ?= /usr/share/telepathy/managers
INSTALL_HAZE_MANAGER ?= 0

# Dependencies via pkg-config (Linux only)
ifeq ($(OS),Windows_NT)
W32_PURPLE_INC ?= /ucrt64/include
W32_GTK_DIR    ?= $(GTK_DIR)
W32_XML_INC    ?= /ucrt64/include/libxml2
W32_LIBDIR     ?= $(CURDIR)/w32lib

PURPLE_CFLAGS  := -I$(W32_PURPLE_INC)/libpurple -I$(W32_PURPLE_INC)/libpurple/win32 -idirafter $(W32_PURPLE_INC)
PURPLE_LIBS    := -L$(W32_LIBDIR) -lpurple

GLIB_CFLAGS    := -I$(W32_GTK_DIR)/include/glib-2.0 -I$(W32_GTK_DIR)/lib/glib-2.0/include
GLIB_LIBS      := -L$(W32_GTK_DIR)/lib -L$(W32_LIBDIR) -lglib-2.0 -lgobject-2.0 -lintl

LIBXML_CFLAGS  := -I$(W32_XML_INC)
LIBXML_LIBS    := -L$(W32_LIBDIR) -lxml2
IMAGE_CFLAGS   := -I$(W32_GTK_DIR)/include/gdk-pixbuf-2.0
IMAGE_LIBS     := -L$(W32_GTK_DIR)/lib -lgdk_pixbuf-2.0
CRYPTO_CFLAGS  ?= -I$(W32_PURPLE_INC)
CRYPTO_LIBS    ?= -L$(W32_LIBDIR) -lcrypto
TLS_CFLAGS     ?= $(CRYPTO_CFLAGS)
TLS_LIBS       ?= -L$(W32_LIBDIR) -lssl
else
PURPLE_CFLAGS  := $(shell pkg-config --cflags purple) $(PURPLE_ADDITIONAL)
PURPLE_LIBS    := $(shell pkg-config --libs purple)

GLIB_CFLAGS    := $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS      := $(shell pkg-config --libs glib-2.0 $(GLIB_ADDITIONAL))

LIBXML_CFLAGS  := $(shell pkg-config --cflags libxml-2.0)
LIBXML_LIBS    := $(shell pkg-config --libs libxml-2.0)
IMAGE_CFLAGS   := $(shell pkg-config --cflags gdk-pixbuf-2.0)
IMAGE_LIBS     := $(shell pkg-config --libs gdk-pixbuf-2.0)
CRYPTO_CFLAGS  := $(shell pkg-config --cflags libcrypto)
CRYPTO_LIBS    := $(shell pkg-config --libs libcrypto)
TLS_CFLAGS     := $(shell pkg-config --cflags libssl)
TLS_LIBS       := $(shell pkg-config --libs libssl)
endif

# Optional GStreamer / voice-video support.
# Auto-detected if USE_VV is unset; pass USE_VV=1 to force on, USE_VV=0 to force off.
# Gentoo ebuilds: USE="gstreamer" → emake USE_VV=1; without → emake USE_VV=0.
ifeq ($(origin USE_VV), undefined)
  GST_CFLAGS := $(shell pkg-config --cflags gstreamer-1.0 2>/dev/null)
  FARSTREAM_CFLAGS := $(shell pkg-config --cflags farstream-0.2 2>/dev/null)
  ifneq ($(strip $(GST_CFLAGS)$(FARSTREAM_CFLAGS)),)
    ifneq ($(GST_CFLAGS),)
      ifneq ($(FARSTREAM_CFLAGS),)
    USE_VV   := 1
    GST_LIBS := $(shell pkg-config --libs gstreamer-1.0 2>/dev/null)
    FARSTREAM_LIBS := $(shell pkg-config --libs farstream-0.2 2>/dev/null)
      else
        USE_VV := 0
      endif
    else
      USE_VV := 0
    endif
  else
    USE_VV   := 0
  endif
endif

ifeq ($(USE_VV), 1)
  ifndef GST_CFLAGS
    GST_CFLAGS := $(shell pkg-config --cflags gstreamer-1.0)
    GST_LIBS   := $(shell pkg-config --libs   gstreamer-1.0)
  endif
  ifndef FARSTREAM_CFLAGS
    FARSTREAM_CFLAGS := $(shell pkg-config --cflags farstream-0.2)
    FARSTREAM_LIBS   := $(shell pkg-config --libs   farstream-0.2)
  endif
  CFLAGS       += $(GST_CFLAGS) $(FARSTREAM_CFLAGS) -DUSE_VV
  LDLIBS_EXTRA  = $(GST_LIBS) $(FARSTREAM_LIBS)
else
  LDLIBS_EXTRA  =
endif

# Final compiler & linker flags
CFLAGS += $(WARN) $(PICFLAG) \
          $(PURPLE_CFLAGS) $(GLIB_CFLAGS) $(LIBXML_CFLAGS) $(AVAHI_CFLAGS) \
          -DBAREV_BUILD_ID=\"$(BAREV_BUILD_ID)\"

CFLAGS += $(IMAGE_CFLAGS) $(CRYPTO_CFLAGS) $(TLS_CFLAGS)
LDLIBS  = $(PURPLE_LIBS) $(GLIB_LIBS) $(LIBXML_LIBS) $(AVAHI_LIBS) $(LDLIBS_EXTRA) $(WIN_LIBS) $(IMAGE_LIBS) $(TLS_LIBS) $(CRYPTO_LIBS) $(SECURITY_UI_LIBS) $(DBUS_LIBS)

PLUGIN  = libbarev.$(EXT)

JINGLE_SRCS = \
  jingle/jingle.c \
  jingle/session.c \
  jingle/transport.c \
  jingle/rawudp.c \
  jingle/content.c

ifeq ($(USE_VV), 1)
  JINGLE_SRCS += jingle/rtp.c
endif

SRCS = \
  barev.c \
  dbus-api.c \
  identity.c \
  tls.c \
  auth-stream.c \
  identity-store.c \
  peer-pins.c \
  pin-ui.c \
  security-ui.c \
  buddy.c \
  avatar-cache.c \
  address.c \
  image-wire.c \
  image-ui.c \
  images.c \
  jabber.c \
  parser.c \
  bonjour_ft.c \
  $(JINGLE_SRCS)

# Windows-specific: Windres for attaching resource file to the plugin
RC_OBJ   :=
RC_FLAGS :=
ifeq ($(OS),Windows_NT)
  ifneq ($(wildcard barev.rc),)
    CC_PATH := $(shell command -v $(CC) 2>/dev/null)
    CC_DIR  := $(dir $(CC_PATH))
    ifeq ($(strip $(WINDRES)),)
      WINDRES := $(firstword $(wildcard $(CC_DIR)i686-w64-mingw32-windres.exe $(CC_DIR)windres.exe))
      ifeq ($(WINDRES),)
        WINDRES  := $(shell command -v windres 2>/dev/null)
        RC_FLAGS := -F pe-i386
      endif
    endif
    ifneq ($(WINDRES),)
      RC_OBJ := barev_res.o
    else
      $(warning windres not found (CC_DIR=$(CC_DIR)), building without barev.rc)
    endif
  endif
endif

OBJS = $(SRCS:.c=.o) $(RC_OBJ)

.PHONY: all clean install uninstall FORCE

all: $(PLUGIN)

$(PLUGIN): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

security-ui.o: $(SOURCE_DIR)/security-ui.c $(SOURCE_DIR)/security-ui.h FORCE
	$(CC) $(CFLAGS) $(SECURITY_UI_CFLAGS) -c "$<" -o "$@"

dbus-interface.inc: $(SOURCE_DIR)/dbus-interface.xml $(SOURCE_DIR)/dbus-xml.py
	$(PYTHON) "$(SOURCE_DIR)/dbus-xml.py" "$<" "$@"

dbus-api.o: $(SOURCE_DIR)/dbus-api.c $(SOURCE_DIR)/dbus-api.h $(if $(filter 1,$(DBUS)),dbus-interface.inc) FORCE
	$(CC) $(CFLAGS) $(DBUS_CFLAGS) -I"$(CURDIR)" -c "$<" -o "$@"

tests/TestDBus: $(SOURCE_DIR)/tests/TestDBus.c $(SOURCE_DIR)/dbus-api.c $(SOURCE_DIR)/dbus-api.h dbus-interface.inc FORCE
	mkdir -p tests
	$(CC) $(CFLAGS) $(LDFLAGS) $(DBUS_CFLAGS) -I"$(SOURCE_DIR)" -I"$(CURDIR)" "$<" "$(SOURCE_DIR)/dbus-api.c" -o "$@" $(DBUS_LIBS)

.PHONY: test-dbus test-dbus-plugin
test-dbus: tests/TestDBus
	dbus-run-session -- "$(abspath tests/TestDBus)" "$(SOURCE_DIR)/dbus-interface.xml"
	DBUS_SESSION_BUS_ADDRESS=unix:path="$(CURDIR)/no-session-bus" "$(abspath tests/TestDBus)" --no-bus

tests/TestDBusPosts: $(SOURCE_DIR)/tests/TestDBusPosts.c $(SOURCE_DIR)/dbus-api.c $(SOURCE_DIR)/dbus-api.h dbus-interface.inc FORCE
	mkdir -p tests
	$(CC) $(CFLAGS) $(LDFLAGS) -std=c11 -Wall -Wextra -Werror $(DBUS_CFLAGS) -I"$(SOURCE_DIR)" -I"$(CURDIR)" "$<" "$(SOURCE_DIR)/dbus-api.c" -o "$@" $(DBUS_LIBS)

.PHONY: test-dbus-publishing
test-dbus-publishing: tests/TestDBusPosts
	dbus-run-session -- "$(abspath tests/TestDBusPosts)"

tests/dbus-plugin-host: $(SOURCE_DIR)/tests/dbus-plugin-host.c $(SOURCE_DIR)/barev.h
	mkdir -p tests
	$(CC) $(CFLAGS) $(LDFLAGS) -I"$(SOURCE_DIR)" "$<" -o "$@" $(LDLIBS) $(shell pkg-config --libs gmodule-2.0)

test-dbus-plugin: $(PLUGIN) tests/dbus-plugin-host
	dbus-run-session -- $(PYTHON) "$(SOURCE_DIR)/tests/check-dbus-plugin.py" "$(CURDIR)" --c

tests/security-ui-test: $(SOURCE_DIR)/tests/security-ui-test.c $(SOURCE_DIR)/tests/security-mock/gtkconv.h $(SOURCE_DIR)/security-ui.c $(SOURCE_DIR)/security-ui.h
	mkdir -p tests
	$(CC) $(CFLAGS) -DBAREV_PIDGIN_UI -I"$(SOURCE_DIR)/tests/security-mock" -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/security-ui-test.c" "$(SOURCE_DIR)/security-ui.c" -o "$@" $(shell pkg-config --libs purple gmodule-2.0 gobject-2.0)

.PHONY: test-security-ui
test-security-ui: tests/security-ui-test
	"$(abspath tests/security-ui-test)"

barev_res.o: barev.rc $(wildcard *.h)
	$(WINDRES) $(RC_FLAGS) --include-dir=. -i barev.rc -o $@ -O coff

# The source revision can change without barev.c's timestamp changing.
barev.o: FORCE
$(OBJS): $(wildcard $(SOURCE_DIR)/*.h $(SOURCE_DIR)/jingle/*.h)
tests/avatar-cache-test: tests/avatar-cache-test.c avatar-cache.c avatar-cache.h
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/avatar-cache-test.c" "$(SOURCE_DIR)/avatar-cache.c" -o "$@" $(LDLIBS)

.PHONY: test-avatar-cache
test-avatar-cache: $(PLUGIN) tests/avatar-cache-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-avatar-cache.py" "$(CURDIR)/tests/avatar-cache-test" "$(abspath $(PLUGIN))"

tests/formatting-test: tests/formatting-test.c jabber.h
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/formatting-test.c" -o "$@" $(LDLIBS) $(shell pkg-config --libs gmodule-2.0)

.PHONY: test-formatting
test-formatting: $(PLUGIN) tests/formatting-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-formatting.py" "$(CURDIR)/tests/formatting-test" "$(abspath $(PLUGIN))"

tests/address-test: tests/address-test.c $(wildcard $(SOURCE_DIR)/*.h)
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/address-test.c" -o "$@" $(LDLIBS) $(shell pkg-config --libs gmodule-2.0)

.PHONY: test-addresses
test-addresses: $(PLUGIN) tests/address-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-addresses.py" "$(CURDIR)/tests/address-test" "$(abspath $(PLUGIN))"

tests/parser-test: tests/parser-test.c parser.c address.c auth-stream.c $(wildcard $(SOURCE_DIR)/*.h)
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/parser-test.c" "$(SOURCE_DIR)/parser.c" "$(SOURCE_DIR)/address.c" "$(SOURCE_DIR)/auth-stream.c" -o "$@" $(LDLIBS) $(shell pkg-config --libs gmodule-2.0)

.PHONY: test-parser
tests/stream-io-test: tests/stream-io-test.c $(wildcard $(SOURCE_DIR)/*.h)
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/stream-io-test.c" -o "$@" $(LDLIBS) $(shell pkg-config --libs gmodule-2.0)

test-parser: $(PLUGIN) tests/parser-test tests/stream-io-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-parser.py" "$(CURDIR)/tests/parser-test" "$(abspath $(PLUGIN))"
	$(PYTHON) "$(SOURCE_DIR)/tests/check-parser.py" "$(CURDIR)/tests/stream-io-test" "$(abspath $(PLUGIN))"

tests/image-ui-test: tests/image-ui-test.c image-ui.c image-ui.h
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/image-ui-test.c" "$(SOURCE_DIR)/image-ui.c" -o "$@" $(LDLIBS) $(shell pkg-config --libs gmodule-2.0)

.PHONY: test-images
tests/image-wire-test: tests/image-wire-test.c image-wire.c image-wire.h
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/image-wire-test.c" "$(SOURCE_DIR)/image-wire.c" -o "$@" $(LDLIBS)

test-images: $(PLUGIN) tests/image-ui-test tests/image-wire-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-images.py" "$(CURDIR)/tests/image-ui-test" "$(abspath $(PLUGIN))"
	"$(CURDIR)/tests/image-wire-test"
FORCE:

tests/identity-test: $(SOURCE_DIR)/tests/identity-test.c $(SOURCE_DIR)/identity.c $(SOURCE_DIR)/identity.h $(SOURCE_DIR)/identity-store.c $(SOURCE_DIR)/identity-store.h
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/identity-test.c" "$(SOURCE_DIR)/identity.c" "$(SOURCE_DIR)/identity-store.c" -o "$@" $(GLIB_LIBS) $(CRYPTO_LIBS)

tests/tls-test: $(SOURCE_DIR)/tests/tls-test.c $(SOURCE_DIR)/tls.c $(SOURCE_DIR)/tls.h $(SOURCE_DIR)/identity.h
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/tls-test.c" "$(SOURCE_DIR)/tls.c" -o "$@" $(GLIB_LIBS) $(TLS_LIBS) $(CRYPTO_LIBS)

.PHONY: test-tls
test-tls: tests/tls-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-tls.py" "$(abspath tests/tls-test)"

tests/auth-stream-test: $(SOURCE_DIR)/tests/auth-stream-test.c $(SOURCE_DIR)/auth-stream.c $(SOURCE_DIR)/auth-stream.h
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/auth-stream-test.c" "$(SOURCE_DIR)/auth-stream.c" -o "$@" $(PURPLE_LIBS) $(GLIB_LIBS)

.PHONY: test-auth-stream
test-auth-stream: tests/auth-stream-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-auth-stream.py" "$(abspath tests/auth-stream-test)"

tests/auth-protocol-host: $(SOURCE_DIR)/tests/auth-protocol-host.c $(wildcard $(SOURCE_DIR)/*.h)
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/auth-protocol-host.c" -o "$@" $(LDLIBS) $(shell pkg-config --libs gmodule-2.0)

.PHONY: test-auth-protocol
test-auth-protocol: $(PLUGIN) tests/auth-protocol-host
	$(PYTHON) "$(SOURCE_DIR)/tests/check-auth-protocol.py" --c "$(abspath tests/auth-protocol-host)" "$(abspath $(PLUGIN))"

.PHONY: test-identities
test-identities: tests/identity-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-identities.py" "$(abspath tests/identity-test)"

tests/PostIOHost: $(SOURCE_DIR)/tests/PostIOHost.c $(SOURCE_DIR)/post-io.c $(SOURCE_DIR)/post-io.h $(SOURCE_DIR)/identity-store.c $(SOURCE_DIR)/identity-store.h
	mkdir -p tests
	$(CC) $(CFLAGS) $(LDFLAGS) -std=c11 -Werror $(GLIB_CFLAGS) -I"$(SOURCE_DIR)" "$<" "$(SOURCE_DIR)/post-io.c" "$(SOURCE_DIR)/identity-store.c" -o "$@" $(GLIB_LIBS) -Wl,--wrap=read,--wrap=__read_chk,--wrap=write,--wrap=fsync,--wrap=close,--wrap=renameat

.PHONY: test-post-io
test-post-io: tests/PostIOHost
	$(PYTHON) "$(SOURCE_DIR)/tests/check-post-io.py" "$(abspath tests/PostIOHost)"

tests/feed-access-test: $(SOURCE_DIR)/tests/feed-access-test.c $(SOURCE_DIR)/feed-access.c $(SOURCE_DIR)/feed-access.h $(SOURCE_DIR)/address.c $(SOURCE_DIR)/address.h
	mkdir -p tests
	$(CC) $(CFLAGS) $(LDFLAGS) -std=c11 -Werror $(PURPLE_CFLAGS) $(GLIB_CFLAGS) -I"$(SOURCE_DIR)" "$<" "$(SOURCE_DIR)/feed-access.c" "$(SOURCE_DIR)/address.c" -o "$@" $(GLIB_LIBS)

.PHONY: test-feed-access
test-feed-access: tests/feed-access-test
	"$(abspath tests/feed-access-test)"

tests/post-store-test: $(SOURCE_DIR)/tests/post-store-test.c $(SOURCE_DIR)/post.c $(SOURCE_DIR)/post.h $(SOURCE_DIR)/post-store.c $(SOURCE_DIR)/post-store.h $(SOURCE_DIR)/feed-access.c $(SOURCE_DIR)/feed-access.h $(SOURCE_DIR)/address.c $(SOURCE_DIR)/address.h
	mkdir -p tests
	$(CC) $(CFLAGS) $(LDFLAGS) -std=c11 -Werror $(PURPLE_CFLAGS) $(GLIB_CFLAGS) -I"$(SOURCE_DIR)" "$<" "$(SOURCE_DIR)/post.c" "$(SOURCE_DIR)/post-store.c" "$(SOURCE_DIR)/feed-access.c" "$(SOURCE_DIR)/address.c" -o "$@" $(GLIB_LIBS)

.PHONY: test-post-store
test-post-store: tests/post-store-test
	"$(abspath tests/post-store-test)"

tests/post-async-test: $(SOURCE_DIR)/tests/post-async-test.c $(SOURCE_DIR)/post-async.c $(SOURCE_DIR)/post-async.h $(SOURCE_DIR)/post.c $(SOURCE_DIR)/post.h $(SOURCE_DIR)/post-store.c $(SOURCE_DIR)/post-store.h $(SOURCE_DIR)/feed-access.c $(SOURCE_DIR)/feed-access.h $(SOURCE_DIR)/address.c $(SOURCE_DIR)/address.h $(SOURCE_DIR)/post-io.c $(SOURCE_DIR)/post-io.h $(SOURCE_DIR)/identity-store.c $(SOURCE_DIR)/identity-store.h
	mkdir -p tests
	$(CC) $(CFLAGS) $(LDFLAGS) -std=c11 -Werror $(PURPLE_CFLAGS) $(GLIB_CFLAGS) -I"$(SOURCE_DIR)" "$<" "$(SOURCE_DIR)/post-async.c" "$(SOURCE_DIR)/post.c" "$(SOURCE_DIR)/post-store.c" "$(SOURCE_DIR)/feed-access.c" "$(SOURCE_DIR)/address.c" "$(SOURCE_DIR)/post-io.c" "$(SOURCE_DIR)/identity-store.c" -o "$@" $(GLIB_LIBS)

.PHONY: test-post-async
test-post-async: tests/post-async-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-post-async.py" "$(abspath tests/post-async-test)"

tests/peer-pins-test: $(SOURCE_DIR)/tests/peer-pins-test.c $(SOURCE_DIR)/peer-pins.c $(SOURCE_DIR)/peer-pins.h $(SOURCE_DIR)/address.c
	mkdir -p tests
	$(CC) $(CFLAGS) -I"$(SOURCE_DIR)" "$(SOURCE_DIR)/tests/peer-pins-test.c" "$(SOURCE_DIR)/peer-pins.c" "$(SOURCE_DIR)/address.c" -o "$@" $(LDLIBS)

.PHONY: test-peer-pins
test-peer-pins: tests/peer-pins-test
	$(PYTHON) "$(SOURCE_DIR)/tests/check-peer-pins.py" "$(abspath tests/peer-pins-test)"

install: $(PLUGIN)
	install -d "$(DESTDIR)$(PLUGIN_DIR)"
	install -m 644 $(PLUGIN) "$(DESTDIR)$(PLUGIN_DIR)"
ifeq ($(INSTALL_HAZE_MANAGER),1)
	install -d "$(DESTDIR)$(TELEPATHY_MANAGER_DIR)"
	install -m 644 haze.manager "$(DESTDIR)$(TELEPATHY_MANAGER_DIR)/haze.manager"
endif
	install -d "$(DESTDIR)$(ICON_DIR)/16"
	install -d "$(DESTDIR)$(ICON_DIR)/22"
	install -d "$(DESTDIR)$(ICON_DIR)/48"
	install -d "$(DESTDIR)$(ICON_DIR)/scalable"
	install -m 644 "logo/16/$(ICON_PNG)" "$(DESTDIR)$(ICON_DIR)/16/barev.png"
	install -m 644 "logo/22/$(ICON_PNG)" "$(DESTDIR)$(ICON_DIR)/22/barev.png"
	install -m 644 "logo/48/$(ICON_PNG)" "$(DESTDIR)$(ICON_DIR)/48/barev.png"
	install -m 644 "logo/scalable/$(ICON_SVG)" "$(DESTDIR)$(ICON_DIR)/scalable/barev.svg"

PIDGIN_WIN_DIR ?= C:/Program Files (x86)/Pidgin

install-win: $(PLUGIN)
	install -d "$(PIDGIN_WIN_DIR)/plugins"
	install -m 644 $(PLUGIN) "$(PIDGIN_WIN_DIR)/plugins/$(PLUGIN)"
	install -d "$(PIDGIN_WIN_DIR)/pixmaps/pidgin/protocols/16" "$(PIDGIN_WIN_DIR)/pixmaps/pidgin/protocols/22" "$(PIDGIN_WIN_DIR)/pixmaps/pidgin/protocols/48" "$(PIDGIN_WIN_DIR)/pixmaps/pidgin/protocols/scalable"
	install -m 644 "logo/16/$(ICON_PNG)" "$(PIDGIN_WIN_DIR)/pixmaps/pidgin/protocols/16/barev.png"
	install -m 644 "logo/22/$(ICON_PNG)" "$(PIDGIN_WIN_DIR)/pixmaps/pidgin/protocols/22/barev.png"
	install -m 644 "logo/48/$(ICON_PNG)" "$(PIDGIN_WIN_DIR)/pixmaps/pidgin/protocols/48/barev.png"
	install -m 644 "logo/scalable/$(ICON_SVG)" "$(PIDGIN_WIN_DIR)/pixmaps/pidgin/protocols/scalable/barev.svg"

uninstall:
	rm -f "$(DESTDIR)$(PLUGIN_DIR)/$(PLUGIN)"
ifeq ($(INSTALL_HAZE_MANAGER),1)
	rm -f "$(DESTDIR)$(TELEPATHY_MANAGER_DIR)/haze.manager"
endif
	rm -f "$(DESTDIR)$(ICON_DIR)/16/barev.png"
	rm -f "$(DESTDIR)$(ICON_DIR)/22/barev.png"
	rm -f "$(DESTDIR)$(ICON_DIR)/48/barev.png"
	rm -f "$(DESTDIR)$(ICON_DIR)/scalable/barev.svg"

clean:
	rm -f $(OBJS) $(PLUGIN) dbus-interface.inc tests/TestDBus tests/dbus-plugin-host
docs:
	pandoc -o barev.pdf barev.md --pdf-engine=xelatex  -V geometry:margin=1in
