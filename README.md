## GVRET dissector plugin (ESP32RET / SavvyCAN binary over TCP).

- Dissects GVRET CMD=0 CAN frames and CMD=0x09 keepalive.
- Dispatches decoded CAN payloads via SocketCAN subdissector mechanism.

Note: there's no warranty of whether this code works for you. It works in my environment, your mileage may vary.

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