CC      ?= gcc
CFLAGS  ?= -g -O2
WARN    ?= -Wall -Wextra -Wno-unused-parameter
PICFLAG ?= -fPIC

# Where to install the plugin:
PLUGIN_DIR := $(shell pkg-config --variable=plugindir purple)

# Where to install icons:
DATADIR := $(shell pkg-config --variable=datadir purple)
ICON_DIR := $(DATADIR)/pixmaps/pidgin/protocols

# Dependencies via pkg-config
PURPLE_CFLAGS  := $(shell pkg-config --cflags purple)
PURPLE_LIBS    := $(shell pkg-config --libs purple)

GLIB_CFLAGS    := $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS      := $(shell pkg-config --libs glib-2.0)

LIBXML_CFLAGS  := $(shell pkg-config --cflags libxml-2.0)
LIBXML_LIBS    := $(shell pkg-config --libs libxml-2.0)

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
          $(PURPLE_CFLAGS) $(GLIB_CFLAGS) $(LIBXML_CFLAGS) $(AVAHI_CFLAGS)

LDLIBS  = $(PURPLE_LIBS) $(GLIB_LIBS) $(LIBXML_LIBS) $(AVAHI_LIBS) $(LDLIBS_EXTRA)

PLUGIN  = libbarev.so

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
  buddy.c \
  jabber.c \
  parser.c \
  bonjour_ft.c \
  $(JINGLE_SRCS)

OBJS = $(SRCS:.c=.o)

.PHONY: all clean install uninstall

all: $(PLUGIN)

$(PLUGIN): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(PLUGIN)
	install -d "$(DESTDIR)$(PLUGIN_DIR)"
	install -m 644 $(PLUGIN) "$(DESTDIR)$(PLUGIN_DIR)"
	install -d "$(DESTDIR)$(ICON_DIR)/16"
	install -d "$(DESTDIR)$(ICON_DIR)/22"
	install -d "$(DESTDIR)$(ICON_DIR)/48"
	install -d "$(DESTDIR)$(ICON_DIR)/scalable"
	install -m 644 logo/16/barev_black.png "$(DESTDIR)$(ICON_DIR)/16/barev.png"
	install -m 644 logo/22/barev_black.png "$(DESTDIR)$(ICON_DIR)/22/barev.png"
	install -m 644 logo/48/barev_black.png "$(DESTDIR)$(ICON_DIR)/48/barev.png"
	install -m 644 logo/scalable/barev.svg "$(DESTDIR)$(ICON_DIR)/scalable/"

uninstall:
	rm -f "$(DESTDIR)$(PLUGIN_DIR)/$(PLUGIN)"
	rm -f "$(DESTDIR)$(ICON_DIR)/16/barev.png"
	rm -f "$(DESTDIR)$(ICON_DIR)/22/barev.png"
	rm -f "$(DESTDIR)$(ICON_DIR)/48/barev.png"
	rm -f "$(DESTDIR)$(ICON_DIR)/scalable/barev.svg"

clean:
	rm -f $(OBJS) $(PLUGIN)
docs:
	pandoc -o barev.pdf barev.md --pdf-engine=xelatex  -V geometry:margin=1in
