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

Not affiliated with, endorsed by, or supported by Pixsee, Compal, CuboAI, or
ThroughTek. Trademarks belong to their respective owners. Use only with devices
and accounts you control.
