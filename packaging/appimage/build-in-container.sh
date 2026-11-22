#!/bin/bash
set -euo pipefail

readonly source_copy=/out/source
readonly appdir=/out/TaskPup.AppDir
readonly appimage=/out/TaskPup-x86_64.AppImage
readonly deploy=/opt/taskpup-build/bin/pyside6-deploy

for output in "$source_copy" "$appdir" "$appimage"; do
    if [[ -e "$output" ]]; then
        printf 'Refusing to overwrite existing build output: %s\n' "$output" >&2
        exit 1
    fi
done

mkdir -p "$source_copy"
printf '%s  %s\n' "$TASKPUP_SOURCE_HASH" /out/source-snapshot.tar | sha256sum --check --status
tar -xf /out/source-snapshot.tar -C "$source_copy"

cd "$source_copy"
export PYTHONPATH="$source_copy/src${PYTHONPATH:+:$PYTHONPATH}"
cp src/taskpup/__main__.py main.py
"$deploy" --init --force --no-install --mode=standalone main.py
"$deploy" --force --no-install --mode=standalone main.py

readonly deployment_dir="$source_copy/build/appimage/standalone"
if [[ ! -d "$deployment_dir" ]]; then
    printf 'pyside6-deploy did not create %s\n' "$deployment_dir" >&2
    exit 1
fi

mapfile -t dist_dirs < <(find "$deployment_dir" -mindepth 1 -maxdepth 1 -type d -name '*.dist' -print)
if [[ ${#dist_dirs[@]} -ne 1 ]]; then
    printf 'Expected one standalone .dist directory in %s; found %s\n' \
        "$deployment_dir" "${#dist_dirs[@]}" >&2
    exit 1
fi

dist_dir="${dist_dirs[0]}"
mapfile -t binaries < <(find "$dist_dir" -maxdepth 1 -type f -name '*.bin' -perm /111 -print)
if [[ ${#binaries[@]} -ne 1 ]]; then
    printf 'Expected one standalone .bin executable in %s; found %s\n' \
        "$dist_dir" "${#binaries[@]}" >&2
    exit 1
fi

if [[ ! -f "$dist_dir/taskpup/TaskPuppyLogo.png" ]]; then
    printf 'Packaged in-app logo is missing from %s\n' "$dist_dir/taskpup" >&2
    exit 1
fi

mkdir -p \
    "$appdir/usr/lib/taskpup" \
    "$appdir/usr/bin" \
    "$appdir/usr/share/applications" \
    "$appdir/usr/share/icons/hicolor/256x256/apps"
cp -a "$dist_dir/." "$appdir/usr/lib/taskpup/"
cp "$source_copy/packaging/appimage/AppRun" "$appdir/AppRun"
chmod 0755 "$appdir/AppRun"
cp "$source_copy/packaging/appimage/taskpup.desktop" "$appdir/usr/share/applications/taskpup.desktop"
cp "$source_copy/assets/branding/appimage-icon.png" \
    "$appdir/usr/share/icons/hicolor/256x256/apps/taskpup.png"
ln -s usr/share/applications/taskpup.desktop "$appdir/taskpup.desktop"
ln -s usr/share/icons/hicolor/256x256/apps/taskpup.png "$appdir/taskpup.png"
ln -s taskpup.png "$appdir/.DirIcon"
if [[ "$(basename "${binaries[0]}")" != taskpup.bin ]]; then
    ln -s "$(basename "${binaries[0]}")" "$appdir/usr/lib/taskpup/taskpup.bin"
fi

desktop-file-validate "$appdir/usr/share/applications/taskpup.desktop"

printf 'Build source commit: %s\n' "${TASKPUP_SOURCE_COMMIT:-unknown}" > /out/build-manifest.txt
printf 'Build mode: %s\nCheckout state at start: %s\n' "$TASKPUP_BUILD_MODE" "$TASKPUP_SOURCE_STATE" >> /out/build-manifest.txt
printf 'Staged source snapshot SHA256: %s\n' "$TASKPUP_SOURCE_HASH" >> /out/build-manifest.txt
printf 'Source date epoch: %s\n' "${SOURCE_DATE_EPOCH:-unset}" >> /out/build-manifest.txt
printf 'Build OS: %s\n' "$(. /etc/os-release && printf '%s %s' "$NAME" "$VERSION_ID")" >> /out/build-manifest.txt
printf 'Build glibc: %s\n' "$(getconf GNU_LIBC_VERSION)" >> /out/build-manifest.txt
printf 'Python: %s\n' "$(/opt/taskpup-build/bin/python --version 2>&1)" >> /out/build-manifest.txt
printf 'PySide6: %s\n' "$(/opt/taskpup-build/bin/python -c 'import PySide6; print(PySide6.__version__)')" >> /out/build-manifest.txt
printf 'Nuitka: %s\n' "$(/opt/taskpup-build/bin/python -m nuitka --version | sed -n '1p')" >> /out/build-manifest.txt
printf 'AppImage tool: 1.9.1\nAppImage runtime: 20251108\n' >> /out/build-manifest.txt
printf 'Build packages:\n' >> /out/build-manifest.txt
/opt/taskpup-build/bin/python -m pip freeze --all >> /out/build-manifest.txt
dpkg-query -W -f='${Package}=${Version}\n' | LC_ALL=C sort >> /out/build-manifest.txt
printf 'Standalone directory: %s\n' "$(basename "$dist_dir")" >> /out/build-manifest.txt
printf 'Standalone executable: %s\n' "$(basename "${binaries[0]}")" >> /out/build-manifest.txt

APPIMAGE_EXTRACT_AND_RUN=1 \
ARCH=x86_64 \
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" \
    /opt/appimagetool-x86_64.AppImage \
        --runtime-file /opt/runtime-x86_64 "$appdir" "$appimage"

file "$appimage" >> /out/build-manifest.txt
stat -c 'AppImage bytes: %s' "$appimage" >> /out/build-manifest.txt
(cd /out && sha256sum "$(basename "$appimage")" > TaskPup-x86_64.AppImage.sha256)
