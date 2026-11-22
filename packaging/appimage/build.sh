#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
output_dir=${TASKPUP_APPIMAGE_OUT:-"$repo_root/build/appimage-experiment"}
image_tag=taskpup-appimage-builder:6.12.0-nuitka-4.3.5
source_commit=$(git -C "$repo_root" rev-parse HEAD)
source_date_epoch=$(git -C "$repo_root" show -s --format=%ct "$source_commit")
build_mode=${TASKPUP_BUILD_MODE:-experimental}
case "$build_mode" in experimental|release) ;; *) printf 'Invalid TASKPUP_BUILD_MODE: %s\n' "$build_mode" >&2; exit 1 ;; esac
source_status=$(git -C "$repo_root" status --porcelain --untracked-files=all)
if [ -n "$source_status" ]; then source_state=dirty; else source_state=clean; fi
if [ "$build_mode" = release ] && [ "$source_state" != clean ]; then
    printf 'Release build requires a clean checkout, including untracked files.\n' >&2
    exit 1
fi

mkdir -p "$(dirname -- "$output_dir")"
if ! mkdir -- "$output_dir"; then
    printf 'Refusing existing or inaccessible build output directory: %s\n' "$output_dir" >&2
    exit 1
fi
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
mkdir "$output_dir/input"
if [ "$build_mode" = release ]; then
    git -C "$repo_root" archive "$source_commit" | tar -xf - -C "$output_dir/input"
else
    cp -a "$repo_root/pyproject.toml" "$repo_root/README.md" "$repo_root/src" "$repo_root/assets" "$repo_root/packaging" "$output_dir/input/"
fi
# The archived snapshot is the source of both the container recipe and compilation.
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -cf "$output_dir/source-snapshot.tar" -C "$output_dir/input" .
source_hash=$(sha256sum "$output_dir/source-snapshot.tar" | cut -d ' ' -f 1)

docker build \
    --platform linux/amd64 \
    --tag "$image_tag" \
    "$output_dir/input/packaging/appimage"

uid=$(id -u)
gid=$(id -g)
docker run --rm \
    --platform linux/amd64 \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user "$uid:$gid" \
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=4g,mode=1777 \
    --tmpfs "/home/taskpup:rw,exec,nosuid,nodev,uid=$uid,gid=$gid,mode=0700,size=128m" \
    --mount "type=bind,source=$output_dir/input,target=/src,readonly" \
    --mount "type=bind,source=$output_dir,target=/out" \
    --workdir /src \
    --env HOME=/home/taskpup \
    --env "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --env "TASKPUP_SOURCE_COMMIT=$source_commit" \
    --env "TASKPUP_SOURCE_STATE=$source_state" \
    --env "TASKPUP_BUILD_MODE=$build_mode" \
    --env "TASKPUP_SOURCE_HASH=$source_hash" \
    "$image_tag" \
    /usr/local/bin/taskpup-appimage-build
