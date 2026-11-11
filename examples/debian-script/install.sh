#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Example install script for firmline-agent: `install.sh <file> <version> <release>`.
# The agent has already checked the file (signature, size and SHA-256 of the signed manifest);
# this script only puts it in place. Install it as /usr/lib/firmline/install.sh, owned by root,
# mode 0755, and point `install = script:/usr/lib/firmline/install.sh` at it.
#
# What the agent gives and expects:
#   - the working folder is /, stdin is /dev/null, only the descriptors 0, 1 and 2 are open;
#   - everything the script prints goes to the agent's log, line by line, prefixed "script: ";
#   - exit 0: installed, and the version source of the component (here /opt/acme/VERSION) already
#     reports <version>. The agent then reports `installed`;
#   - exit 10: installed, but it takes effect at the next boot. The agent runs `reboot_command`
#     when the configuration has one, otherwise this script must reboot the device itself. After
#     the boot the agent reads the version: the new one is `installed`, anything else is
#     `failed boot_failed`. Use it when the new file is only activated at boot (a new root file
#     system, a kernel); this example does not need it;
#   - any other exit code, or no exit within `timeout`, is `failed install_failed`.
set -eu
# The character ranges below are the ASCII ones, whatever the locale of the device.
LC_ALL=C
export LC_ALL

target_dir=/opt/acme
target="$target_dir/app"
version_file="$target_dir/VERSION"

if [ "$#" -ne 3 ]; then
    echo "usage: install.sh <file> <version> <release>" >&2
    exit 2
fi
file=$1
version=$2
release=$3

if [ ! -f "$file" ] || [ ! -r "$file" ]; then
    echo "the file $file cannot be read" >&2
    exit 2
fi
# The version goes into a file the agent reads back: one line of at most 64 safe characters.
case $version in
    '' | *[!A-Za-z0-9._+-]*)
        echo "the version has characters this example does not accept" >&2
        exit 2
        ;;
esac
if [ "${#version}" -gt 64 ]; then
    echo "the version is longer than 64 characters" >&2
    exit 2
fi

echo "installing release $release, version $version"
mkdir -p "$target_dir"

# Copy next to the target, then rename: the application file is never half written.
tmp="$target.new.$$"
trap 'rm -f "$tmp" "$version_file.new.$$"' EXIT
cp "$file" "$tmp"
chmod 0755 "$tmp"
sync "$tmp"
mv -f "$tmp" "$target"

# The version file last: it says "installed" only when the file is in place.
printf '%s\n' "$version" >"$version_file.new.$$"
sync "$version_file.new.$$"
mv -f "$version_file.new.$$" "$version_file"

# Make the renames durable. `sync <path>` needs coreutils 8.24 or later (Debian 9 and later); on an
# older system use plain `sync`.
sync "$target_dir"

# Restart the application (adapt to your device). The file is installed and the version file is
# written: a failed restart is logged, but it must not turn an installed file into install_failed.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet acme-app.service; then
    systemctl restart acme-app.service || echo "warning: acme-app.service did not restart" >&2
fi
echo "installed"
exit 0
