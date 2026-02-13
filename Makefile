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

# Final compiler & linker flags
CFLAGS += $(WARN) $(PICFLAG) \
          $(PURPLE_CFLAGS) $(GLIB_CFLAGS) $(LIBXML_CFLAGS) $(AVAHI_CFLAGS)

LDLIBS  = $(PURPLE_LIBS) $(GLIB_LIBS) $(LIBXML_LIBS) $(AVAHI_LIBS)

PLUGIN  = libbarev.so

SRCS = \
  bonjour.c \
  buddy.c \
  jabber.c \
  parser.c \
  bonjour_ft.c

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
	install -m 644 logo/16/barev.png "$(DESTDIR)$(ICON_DIR)/16/"
	install -m 644 logo/22/barev.png "$(DESTDIR)$(ICON_DIR)/22/"
	install -m 644 logo/48/barev.png "$(DESTDIR)$(ICON_DIR)/48/"
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

