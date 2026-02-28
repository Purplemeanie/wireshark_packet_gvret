## GVRET → CAN Wireshark Plugin

This plugin is a **GVRET transport dissector** that reconstructs and exposes embedded CAN frames as **native Wireshark CAN packets**, then dispatches them through Wireshark’s standard CAN dissector tables. It is designed to make GVRET traffic behave like a normal CAN capture inside Wireshark, enabling reuse of the existing CAN protocol ecosystem (ISO-TP, J1939, UDS, custom signal decoders, etc.).

### Tested on

-------------
| Wireshark | 4.7.0 |
| MacOS | 26.1 |
| Ubuntu | 6.17.0 |
-------------

This plugin has been developed and tested on Apple Silicon with MacOS26. It may or may not work on other OS'es.

### What This Plugin Decodes

- **GVRET framing over TCP** (commonly port 23, but works on any TCP port once selected/decoded)
- **`CMD=0x00` CAN frame packets**
- **`CMD=0x09` keepalive packets** (decoded for visibility and stream sanity)

For each `CMD=0x00` CAN frame, the plugin:
1. parses timestamp / bus / ID / DLC / data,
2. creates a native Wireshark CAN layer,
3. sets the appropriate CAN metadata fields (e.g. `can.id`, frame type),
4. **hands off decoding** via Wireshark’s CAN dissector mechanism (so other dissectors decode payloads).

---

## Layering (End-to-End)

Once GVRET has been decoded, the resulting packet stack in Wireshark looks like this:

```
Ethernet
└── IPv4 / IPv6
└── TCP
└── GVRET (transport)
└── CAN (reconstructed frame)
├── ISO-TP (ISO 15765-2)        [optional, based on CAN ID + dissector]
│   └── UDS / Diagnostics       [optional, runs on top of ISO-TP]
├── J1939                      [optional, PGN-based decoding]
├── CANopen / NMT / SDO / PDO   [optional]
├── UAVCAN / DroneCAN           [optional]
└── Custom Signal Decoders      [optional; e.g. DBC-derived]
```

### Multiple CAN Frames per GVRET Packet

A single GVRET TCP segment can contain multiple CAN frames. Wireshark will display them as multiple CAN subtrees under the GVRET node, each independently dispatching to the correct higher-layer dissector:

```
GVRET
├── CAN (ID 0x338, DLC 8)
│   └── DEVICE 1 LUA SCRIPT
├── CAN (ID 0x308, DLC 8)
│   └── DEVICE 2 LUA SCRIPT
└── CAN (ID 0x18DAF110, DLC 8)
└── ISO-TP
└── UDS
```

It might be better to add a UDP transport to the GVRET protocol so we can dispatch single CAN frames via GVRET... And therefore have only one CAN frame per Wireshark frame.

---

## Dispatch / Plugin Interop Model

This is the key idea: the GVRET plugin is **not** a monolithic signal decoder. It is a **transport + CAN reconstruction layer** that enables other dissectors to work unchanged.

```
TCP stream
|
v
GVRET dissector
|  (parses CMD=0x00 / CMD=0x09)
v
Reconstructed CAN frame
|  (populates Wireshark CAN fields like can.id)
v
Wireshark CAN dissector tables
|
+–> ISO-TP dissector  –> UDS / Diagnostics
|
+–> J1939 dissector   –> PGNs / SPNs
|
+–> Custom CAN ID dissectors (e.g. BDC668)
|
\–> Any other CAN ecosystem dissector
```

Because dispatch is done using Wireshark’s normal mechanism, multiple CAN-based dissectors can coexist: e.g. BDC668 decoding some IDs while ISO-TP/UDS or J1939 decode others in the same capture.

---

## Why This Matters

Reconstructing true Wireshark CAN frames (instead of decoding payloads privately inside GVRET) gives:

- **Correct protocol layering** in the packet details pane (GVRET → CAN → ISO-TP → UDS, or GVRET → CAN → J1939, etc.)
- **Compatibility with existing Wireshark dissectors** and tooling
- **Decode-As support** (you can attach different CAN sub-dissectors without modifying the GVRET plugin)
- **Multiple decoders at once** (signal decoder + ISO-TP + J1939 in the same capture)
- A clean mental model: **GVRET is the transport**, Wireshark’s CAN stack does the rest


### My MacOS .so Build Instructions:

```bash
git clone <wireshark-source>
brew install lua, asciidoctor
mkdir -p <wireshark-source-directory>/plugins/epan/gvret
```

Copy the files in this directory (i.e. CMakeLists.txt, packet-gvret.c and the README.md) into wireshark/plugins/epan/gvret/
Copy the CMakeListsCustom.txt to the top level wireshark directory:

Then to build wireshark...

```bash
cd wireshark
mkdir build
cd build
cmake ..
cmake --build .
```

### Building and Fixing DMG signing

```bash
brew install asciidoctor (already installed from above)
pipx install dmgbuild
cmake -S .. -B . -DDMGBUILD_EXECUTABLE="$HOME/.local/bin/dmgbuild"
cmake --build . --target wireshark_dmg
; Now turn off the App seciurity or sign the app if you want to
sudo xattr -cr /Applications/Wireshark.app
sudo codesign --force --deep --sign - /Applications/Wireshark.app
codesign --verify --deep --strict --verbose=4 /Applications/Wireshark.app
```

Once the correct version of Wireshark has been built and installed then you can just copy new versions of gvret.so into:

```bash
cp run/Wireshark.app/Contents/PlugIns/wireshark/4-7/epan/gvret.so /Applications/Wireshark.app/Contents/PlugIns/wireshark/4-7/epan
```
