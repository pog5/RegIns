RegIns 1.0.0
Author: Nightly
Configuration: Release | Architecture: x64
Self-contained .NET 11 preview runtime included; no .NET installation required.

Choose ONE platform folder and keep all its files together:
  win-x64          Windows: launch RegIns.Gui.exe or RegIns.Cli.exe
  linux-x64        Standard glibc Linux: ./RegIns.Gui or ./RegIns.Cli
  linux-musl-x64   Alpine Linux: ./RegIns.Gui or ./RegIns.Cli
  library          Managed RegIns.Core.dll and NuGet package (net11.0)

On Linux, if your ZIP extractor loses execute permissions:
  chmod +x RegIns.Gui RegIns.Cli

Alpine x64 dependencies (run as root):
  apk add libstdc++ libgcc icu-libs zlib openssl ca-certificates
For the GUI also install:
  apk add libx11 libice libsm fontconfig libxext libxrender libxi font-dejavu mesa-egl mesa-gl
The GUI needs a running X11 desktop or XWayland with DISPLAY set.
Headless boot media should use the CLI. System libraries are not bundled.

Example commands from your selected platform folder:
  ./RegIns.Cli recover /path/to/SYSTEM --out plan.json
  ./RegIns.Cli export plan.json --out SYSTEM.recovered
  ./RegIns.Cli validate SYSTEM.recovered
On Windows use .\RegIns.Cli.exe instead of ./RegIns.Cli.

Release checks:
  Release solution build: zero warnings/errors; 18 behavior tests passed.
  Windows packaged CLI: clean fixture validation passed.
  Alpine 3.24.1 musl environment: recover/export/validate round trip passed.
  Alpine GUI: startup/liveness smoke test under Xvfb passed (8 seconds).
  Alpine GUI interaction and real-desktop integration were not tested.
  Windows GUI interaction was tested before this metadata-only rebuild.

The 1.0.0 label is the requested distribution version. Recovery remains
experimental: see SUPPORT.md and ENGINE-README.md for implemented boundaries.
Normal Windows loading of the supplied SYSTEM recovery remains unresolved.
No private hives, recovered machine data, or recovery plans are in this ZIP.
