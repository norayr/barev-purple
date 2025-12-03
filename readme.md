

# Compile

## Dependencies

On Gentoo: pidgin, avahi

On Debian: libpurple-dev, libavahi-client-dev, libavahi-glib-dev, libxml2-dev

## Actual build

```
git pull https://github.com/norayr/barev
cd barev
make
```

then
```
sudo make install
```
or just manually copy libbarev.so to ~/.purple/plugins
```
cp libbarev.so ~/.purple/plugins
```

restart pidgin.

