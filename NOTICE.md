# Attribution

This project is derived from [Fredde87/cuboai-tutk](https://github.com/Fredde87/cuboai-tutk),
base commit `3d4f575f0a972dbca5067593026784c0c9e42264`, under the MIT license.
The original copyright and permission notice are retained in LICENSE and git history.

Retained upstream modules: `cuboai_pure.py`, `cuboai_messages.py`, `cuboai_pts.py`,
and `cuboai_mpegts.py`. The transport adds default-preserving hooks for Pixsee
media classification and final frame validation; the original Cubo-specific
connection routines are not used by the Pixsee entry point.

The Pixsee modules are an independent interoperability implementation based on
static inspection of the user-supplied Pixsee Android 4.030.006 package and
bounded tests against an owned camera. No vendor binaries, decompiled source,
private media, raw packet captures, or per-device credentials are distributed.
App-default profile constants are explicitly identified in `pixsee_config.py`.

## Protocol gateway dependencies

The gateway invokes separately installed MediaMTX **v1.21.3**, FFmpeg and FFprobe.
It does not bundle their binaries or copy their implementation into the Python modules.

- [MediaMTX v1.21.3](https://github.com/bluenviron/mediamtx/tree/9540cb6c1d9f1e9351fcc4ded3afc249ffff22bc)
  is distributed under the [MIT license](https://github.com/bluenviron/mediamtx/blob/9540cb6c1d9f1e9351fcc4ded3afc249ffff22bc/LICENSE),
  copyright 2019 aler9. Preserve its notices when redistributing that component.
- [FFmpeg licensing](https://ffmpeg.org/legal.html) depends on the configured build and
  linked components. Installing or invoking it does not relicense this project's
  original code; distributing an FFmpeg build requires following that build's terms.
- `pixsee_onvif.py` and `pixsee_discovery.py` independently implement a bounded subset
  of the published ONVIF and WS-Discovery interfaces. The GPL-3.0
  `roleoroleo/onvif_simple_server` project was examined only as an architecture reference;
  none of its code or XML response templates are included.
- Scrypted and node-onvif were inspected to understand client interoperability.
  No Scrypted implementation is bundled, and this project does not claim Scrypted
  product acceptance or ONVIF Profile S/T certification.

Pinned sources and the implementation decision are recorded in
[the protocol gateway research](docs/research/protocol-gateway.md).

Not affiliated with, endorsed by, or supported by Pixsee, Compal, CuboAI, or
ThroughTek. Trademarks belong to their respective owners. Use only with devices
and accounts you control.
