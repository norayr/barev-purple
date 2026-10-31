# Conversation pictures

Barev's Pidgin **Insert / Image** action sends static PNG/JPEG pictures over an
established contact's messaging connection. For large pictures, choose
**Fit for chat**, **Send original**, or **Cancel**. Fitting creates a copy at
most 1280 pixels on its longest side and 256 KiB, preserving the source file.
The default prompt threshold is 256 KiB; pictures at least 1280 pixels wide or
tall also qualify. Advanced account options select `ask`, `fit`, or `original`
and configure the resizing, automatic-receive, and BoB thresholds.

**Send File** preserves the original through the existing SI/SOCKS5 transfer
on ports 50000–50049. Successfully received PNG/JPEG files also get a preview.

## Receiving and storage

The receiver independently controls automatic acceptance, defaulting to 256 KiB.
Larger originals require acceptance and a save location through libpurple's
file-transfer dialog. IBB original transfers expose progress and cancellation;
closing the messaging stream cancels them.

Setting automatic acceptance to zero asks for every image. BoB references do
not announce a byte size, so thresholds below the 256 KiB BoB ceiling require
permission before fetching an uncached reference. Fetched objects must still
fit the ceiling and pass content-ID and image validation.

Previews are at most 640 pixels on their longest side and live in libpurple's
image store. HTML conversation logging saves previews beside logs under
`~/.purple/logs/<protocol>/<account>/<contact>/`. Logging-disabled conversations
do not create a separate attachment cache. Accepted originals go only to the
receiver's chosen save location.

## Interoperability and limits

Inline images use XHTML-IM `cid:` references with **XEP-0231 BoB** retrieval.
The default BoB sending threshold is 64 KiB, configurable from 1 to 256 KiB.
Barev supports SHA-1 BoB content IDs. Larger images use standard
**XEP-0095 / XEP-0096 SI offers** selecting **XEP-0047 IBB**, paced by IQ
acknowledgements to 4096-byte chunks.

Static PNG/JPEG images are limited to 16 MiB, 8192 pixels per dimension, and
16 megapixels. Protocol image storage is globally bounded to 64 MiB, with eight
cached objects and four pending BoB references per peer. Each peer supports one
incoming and one outgoing IBB original; send multiple large originals
individually. Request/offer budgets, bounded stanza queues, sequence checks, and
120-second consent/idle deadlines bound resource use.

## Dependencies and tests

`make test-images` runs the C image engine and native UI tests without opening
peer connections.

Building additionally requires `gdk-pixbuf-2.0` development files and PNG/JPEG
loaders (`libgdk-pixbuf-2.0-dev` on Debian, `x11-libs/gdk-pixbuf` on Gentoo).
Windows builds use GdkPixbuf from the GTK development bundle selected by
`W32_GTK_DIR`.

The Oberon repository provides isolated bidirectional C/Oberon BoB/IBB fixtures:

```sh
BAREV_C_IMAGE_LIBRARY=/absolute/path/to/libbarev.so make image-test
```

Run that command in the Oberon repository with its VOC/libpurple dependencies
available. It uses disposable profiles and IPv6 loopback sockets.
