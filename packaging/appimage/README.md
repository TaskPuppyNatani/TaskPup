# TaskPup experimental AppImage

Build one x86_64 Type 2 AppImage from the repository root:

```sh
./packaging/appimage/build.sh
```

The build uses a digest-pinned Ubuntu 24.04/Noble container so the output targets
Mint 22.3's glibc baseline. Python, PySide6, Nuitka, psutil, `appimagetool`, and
the Type 2 runtime are pinned in the build files. The build container reads the
checkout read-only, writes only under `build/appimage-experiment/`, and has no network
access while compiling or packaging.

Each run requires a new output directory. Set `TASKPUP_APPIMAGE_OUT` to an
unused absolute path for subsequent builds. Experimental builds record the
checkout revision and its starting clean/dirty status, plus the SHA-256 of
`source-snapshot.tar`, the exact staged source used for compilation. Keep the
snapshot with the manifest to audit uncommitted and untracked inputs.
For a release build, set `TASKPUP_BUILD_MODE=release`; it requires a clean
checkout, including untracked files, and stages the recorded Git revision.

The base image is digest pinned; Python and the listed Python packages are
version pinned, and appimagetool and its runtime are checksum verified. Apt
repositories and several apt package versions remain mutable, and Python
packages are not hash locked. The manifest records installed package versions.
The source snapshot identifies source inputs; it does not establish byte-for-byte
reproducible binaries. Process priority and affinity operations have a separate
PID-reuse safety question that requires a pre-public-release decision.

The AppDir keeps the standalone `.dist` layout intact. Its `AppRun` prepends
the bundled desktop-data directory to `XDG_DATA_DIRS` and sets
`TASKPUP_APPIMAGE_ICON` to the bundled window icon; it leaves host command
lookup, D-Bus, Polkit, portal, display, GPU, XDG configuration, and application
data environment settings available to TaskPup.

`assets/TaskPuppyLogo.png` remains the Qt in-app logo and is placed beside the
packaged `taskpup` module. `assets/branding/appimage-logo.png` remains the
approved artwork. `assets/branding/appimage-icon.png` is a separate 256 px
launcher derivative cropped to the dog profile and neon ring; it is used only
for AppImage and desktop-launcher branding.

An unintegrated AppImage can report that the desktop portal cannot find the
`taskpup` app ID: the portal service searches its own host desktop database,
not the AppImage process's `XDG_DATA_DIRS`. This warning was nonfatal on LMDE 7;
the save dialog and exports worked. No desktop entry is installed automatically.

Generated standalone output, AppDir, manifest, checksum, and AppImage are written
under the ignored `build/` directory. The build stops instead of overwriting an
existing experiment output.
