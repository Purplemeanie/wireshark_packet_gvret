## GVRET → CAN Wireshark Plugin

This plugin is a **GVRET transport dissector** that reconstructs and exposes embedded CAN frames as **native Wireshark CAN packets**, then dispatches them through Wireshark’s standard CAN dissector tables. It is designed to make GVRET traffic behave like a normal CAN capture inside Wireshark, enabling reuse of the existing CAN protocol ecosystem (ISO-TP, J1939, UDS, custom signal decoders, etc.).

### Tested on

| Name      | Version |
|-----------|---------|
| Wireshark | 4.7.0   |
| MacOS     | 26.1    |
| Ubuntu    | 6.17.0  |
| Windows10 | Not tested |
| Windows11 | Not tested |

This plugin has been developed and tested on Apple Silicon Macs with MacOS26. It may or may not work on other OS'es.

### What This Plugin Decodes

- **GVRET framing over TCP** (commonly port 23, but works on any TCP port once selected/decoded. Port can be selected in the Wireshark settings for this GVRET protocol)
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
├── CAN (ID 0xNNN, DLC 8)
│   └── DEVICE 1 LUA SCRIPT
├── CAN (ID 0xNNN, DLC 8)
│   └── DEVICE 2 LUA SCRIPT
└── CAN (ID 0xNNNNNNNN, DLC 8)
└── ISO-TP
└── UDS
```

At some point it might be better to add a UDP transport to the GVRET protocol so we can dispatch single CAN frames via GVRET... And therefore have only one CAN frame per Wireshark frame.

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

Because dispatch is done using Wireshark’s normal mechanism, multiple CAN-based dissectors can coexist: e.g. decoding some IDs while ISO-TP/UDS or J1939 decode others in the same capture.

Reconstructing true Wireshark CAN frames (instead of decoding payloads privately inside GVRET) gives:

- **Correct protocol layering** in the packet details pane (GVRET → CAN → ISO-TP → UDS, or GVRET → CAN → J1939, etc.)
- **Compatibility with existing Wireshark dissectors** and tooling
- **Decode-As support** (you can attach different CAN sub-dissectors without modifying the GVRET plugin)
- **Multiple decoders at once** (signal decoder + ISO-TP + J1939 in the same capture)
- A clean mental model: **GVRET is the transport**, Wireshark’s CAN stack does the rest

## Building the Plugin

There's a couple of ways of building the plugin:
- In-tree and
- Out-of-tree

IMHO the in-tree method is by far the easiest (though I'm still working on ways to get the out-of-tree working too). In-tree means you build the plugin as part of building the whole of Wireshark. Out-of-tree means you just build the plugin by also linking against the header files from the Wireshark source.

Then once you have the plugin built there's a couple of ways to deploy it:
- Inside the main Wireshark installation
- In the personal plugin's directory

You can do either of these installations whether you do in-tree or out-of-tree compilation.

In theory the least invassive approach to installation is to use the personal plugin directory. However, the plugin needs to be built against the specific version of Wireshark that it's going to be used with. So, I've always ended up building the whole of Wireshark and just installing it all with a DMG on my Mac's.

But... the theory goes that you can build this plugin, put it in the personal plugin dirctory and then be able to update your main Wireshark installation without it overwriting your plugin. I need more time to look into this and see what can actually be achieved.

### My MacOS In-Tree .so Build Instructions:

Perhaps the simplest way to build this plugin is in-tree. These are the steps I've found to work:

```bash
git clone <wireshark-source>
brew install lua, asciidoctor
mkdir -p <wireshark-source-directory>/plugins/epan/gvret
```

(you may find you need other dependencies installing via brew)

Copy the files in this directory. i.e. from wherever you have the gvret plugin source installed:

```
cp CMakeListsCustom.txt <wireshark-source-directory>
mkdir -p <wireshark-source-directory>/plugins/epan/gvret
cp packet-gvret.c CMakeLists.txt <wireshark-source-directory>/plugins/epan/gvret
```

Then to build wireshark...

```bash
cd <wireshark-source-directory>
mkdir build
cd build
cmake ..
cmake --build .
```

### Out-of-tree Build Instructions

[TODO]

## Installation

### MacOS

#### Install with the whole of Wireshark

Now you've built a full version of Wireshark, perhaps the easiest thing to do is just install the whole of the application, including this plugin. That will put the plugin into the application's library structure. In the case of a Mac that puts the plugin into:

```bash
/Applications/Wireshark.app/Contents/PlugIns/wireshark/4-7/epan/gvret.so
```

The downside of this approach is that if you were to install a newer version of Wireshark from a downloaded DMG, then it would overwrite the gvret.so plugin and it would no longer be loaded and disect any GVRET messages.

To build and install a complete installation of Wireshark including the plugin, you either need to sign the install (not covered here), or remove the security lockdown of the App once installed (this may be a good reason why you'd want to go down the personal plugins directory route):

```bash
brew install asciidoctor (already installed from above)
pipx install dmgbuild
cmake -S .. -B . -DDMGBUILD_EXECUTABLE="$HOME/.local/bin/dmgbuild"
cmake --build . --target wireshark_dmg
```

Now install Wireshark from the DMG file you just created, for 4.7 this would be:

```bash
./run/Wireshark\ 4.7.0\ Arm\ 64.dmg
```

Now turn off the App seciurity OR sign the app if you want to. Here's how to turn off the app security:

```bash
sudo xattr -cr /Applications/Wireshark.app
sudo codesign --force --deep --sign - /Applications/Wireshark.app
codesign --verify --deep --strict --verbose=4 /Applications/Wireshark.app
```

#### Install just the gvret.so plugin into an existing Wirehsark installation

If you've downloaded the same version of the Wireshark source as you already have installed on your computer then it is now possible to just install the plugin into the already installed Wireshark.

```bash
cp run/Wireshark.app/Contents/PlugIns/wireshark/4-7/epan/gvret.so /Applications/Wireshark.app/Contents/PlugIns/wireshark/4-7/epan
```

#### Personal Plugins

Following on from the in-tree build instructions:

If you've downloaded the same version of the Wireshark source as you already have installed on your computer then it is now possible to just install the plugin into the personal plugins folder (this may also work if your Wireshark install has the same major.minor versioning as the source you used to build the plugin, TBD).

```bash
cp run/Wireshark.app/Contents/PlugIns/wireshark/4-7/epan/gvret.so ~/.local/lib/wireshark/plugins/4.7/epan/gvret.so
```

(Chagne 4.7 to whatever version of Wireshark you built for)

If you're going to do this personal plugin route then for some reason I also had to install xxhash:

```bash
brew install xxhash
```

## Linux Installtion

Build instructions are generally as described in the in-tree build instructions above (download Wireshark source, add the plugin files into the Wireshark source tree). 

However, there will be various libs and dependencies that will also need to be installed to satisfy the linking of the final plugin. These installs will vary wildly depending on what you've already got installed, but may include:

- QT5 and/or QT6
- QML
- SpeexDSP

Once all those dependencies have been resolved and you've built the Wireshark application, then you have similar options to those on a Mac:
- Install all of Wireshark
- Install the plugin into an existing Wireshark installation (of the same version as the Wireshark source you built from)
- Install the plugin into the personal plugins folder

[TODO - replicate similar MacOS install instruction]


(Be mindful that on Ubuntu you often need to run Wireshark with sudo and so the ~ will be root not necessarily your login user)

## Windows Installation

[TODO]

## Todo

- Think about using UDP instead of TCP for GVRET transmission. That way single GVRET packets can be pushed out onto the wifi and will appear in Wireshark as single frames. This is inefficient and throughput will have to be tested.
