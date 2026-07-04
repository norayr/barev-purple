PLUGIN = libbarev.so
ACCOUNT_PLUGIN = libbarev-plugin.so

SRCS = \
  bonjour.c \
  buddy.c \
  jabber.c \
  parser.c \
  bonjour_ft.c

OBJS = $(SRCS:.c=.o)
ACCOUNT_OBJS = account-plugin.o

# Compiler and linker flags
CFLAGS := -I/usr/include/libpurple -I/usr/include/glib-2.0 -I/usr/lib/arm-linux-gnueabihf/glib-2.0/include $(shell pkg-config --cflags libxml-2.0)
LDLIBS := -lpurple -lglib-2.0 $(shell pkg-config --libs libxml-2.0)

# Flags for the account plugin
ACCOUNT_CFLAGS := -I/usr/include/glib-2.0 -I/usr/lib/arm-linux-gnueabihf/glib-2.0/include $(shell pkg-config --cflags rtcom-accounts-widgets libglade-2.0 telepathy-glib gtk+-2.0)
ACCOUNT_LDLIBS := $(shell pkg-config --libs rtcom-accounts-widgets libglade-2.0 telepathy-glib gtk+-2.0) -lglib-2.0

.PHONY: all clean install uninstall

all: $(PLUGIN) $(ACCOUNT_PLUGIN)

$(PLUGIN): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDLIBS)

$(ACCOUNT_PLUGIN): $(ACCOUNT_OBJS)
	$(CC) -shared -o $@ $(ACCOUNT_OBJS) $(ACCOUNT_LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

account-plugin.o: account-plugin.c
	$(CC) $(ACCOUNT_CFLAGS) -c $< -o $@

install: $(PLUGIN) $(ACCOUNT_PLUGIN)
	install -d "$(DESTDIR)/usr/lib/purple-2"
	install -m 644 $(PLUGIN) "$(DESTDIR)/usr/lib/purple-2/"
	install -d "$(DESTDIR)/usr/lib/arm-linux-gnueabihf/libaccounts-plugins"
	install -m 644 $(ACCOUNT_PLUGIN) "$(DESTDIR)/usr/lib/arm-linux-gnueabihf/libaccounts-plugins/"
	install -d "$(DESTDIR)/usr/lib/arm-linux-gnueabihf/libaccounts-plugins/xml"
	install -m 644 data/barev-advanced.glade "$(DESTDIR)/usr/lib/arm-linux-gnueabihf/libaccounts-plugins/xml/"
	install -d "$(DESTDIR)/usr/share/pixmaps/pidgin/protocols/16"
	install -d "$(DESTDIR)/usr/share/pixmaps/pidgin/protocols/22"
	install -d "$(DESTDIR)/usr/share/pixmaps/pidgin/protocols/48"
	install -d "$(DESTDIR)/usr/share/pixmaps/pidgin/protocols/scalable"
	install -m 644 logo/16/barev.png "$(DESTDIR)/usr/share/pixmaps/pidgin/protocols/16/"
	install -m 644 logo/22/barev.png "$(DESTDIR)/usr/share/pixmaps/pidgin/protocols/22/"
	install -m 644 logo/48/barev.png "$(DESTDIR)/usr/share/pixmaps/pidgin/protocols/48/"
	install -m 644 logo/scalable/barev.svg "$(DESTDIR)/usr/share/pixmaps/pidgin/protocols/scalable/"
	install -d "$(DESTDIR)/usr/share/icons/hicolor/48x48/hildon"
	install -m 644 logo/48/barev.png "$(DESTDIR)/usr/share/icons/hicolor/48x48/hildon/im-barev.png"
	install -d "$(DESTDIR)/usr/share/accounts/providers"
	install -m 644 data/barev.provider "$(DESTDIR)/usr/share/accounts/providers/"
	install -d "$(DESTDIR)/usr/share/accounts/services"
	install -m 644 data/barev.service "$(DESTDIR)/usr/share/accounts/services/"

clean:
	rm -f $(OBJS) $(ACCOUNT_OBJS) $(PLUGIN) $(ACCOUNT_PLUGIN)