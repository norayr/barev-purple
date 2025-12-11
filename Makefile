CC      ?= gcc
CFLAGS  ?= -g -O2
WARN    ?= -Wall -Wextra -Wno-unused-parameter
PICFLAG ?= -fPIC

# Where to install the plugin:
PLUGIN_DIR := $(shell pkg-config --variable=plugindir purple)

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

.PHONY: all clean install

all: $(PLUGIN)

$(PLUGIN): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(PLUGIN)
	install -d "$(DESTDIR)$(PLUGIN_DIR)"
	install -m 644 $(PLUGIN) "$(DESTDIR)$(PLUGIN_DIR)"

clean:
	rm -f $(OBJS) $(PLUGIN)
docs:
	pandoc -o barev.pdf barev.md --pdf-engine=xelatex  -V geometry:margin=1in

