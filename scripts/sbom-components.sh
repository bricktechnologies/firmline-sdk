#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Adds to a CycloneDX JSON SBOM the components Syft cannot find: the agent itself, Mbed TLS
# (statically linked: it verifies the update signatures) and jsmn (vendored). Usage:
#   scripts/sbom-components.sh <sbom.cdx.json> <agent version X.Y.Z>
# The Mbed TLS version is read from cmake/mbedtls.cmake (its release tarball URL), the jsmn version
# from core/third_party/jsmn/VERSION; a version that cannot be read stops the script (exit 1).
# The file is changed in place. Running it again replaces the three components, never duplicates
# them (they are recognised by their bom-ref).
set -euo pipefail

die() {
    echo "sbom-components: $*" >&2
    exit 1
}

[ "$#" -eq 2 ] || die "usage: $0 <sbom.cdx.json> <agent version>"
sbom=$1
agent_version=$2
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

command -v jq >/dev/null || die "jq is required"
[ -f "$sbom" ] || die "$sbom does not exist"
[[ "$agent_version" =~ $semver ]] || die "'$agent_version' is not a version X.Y.Z"

mbedtls_file="$root/cmake/mbedtls.cmake"
[ -f "$mbedtls_file" ] || die "cannot read the Mbed TLS version: $mbedtls_file does not exist"
mapfile -t mbedtls_versions < <(grep -oE 'mbedtls-[0-9]+\.[0-9]+\.[0-9]+\.tar' "$mbedtls_file" \
    | sed -E 's/^mbedtls-//; s/\.tar$//' | sort -u)
[ "${#mbedtls_versions[@]}" -eq 1 ] \
    || die "cannot read the Mbed TLS version from cmake/mbedtls.cmake (expected one release tarball mbedtls-X.Y.Z.tar.*, found ${#mbedtls_versions[@]})"
mbedtls_version=${mbedtls_versions[0]}

jsmn_file="$root/core/third_party/jsmn/VERSION"
[ -f "$jsmn_file" ] || die "cannot read the jsmn version: $jsmn_file does not exist"
jsmn_version=$(head -n 1 "$jsmn_file" | tr -d '[:space:]')
[[ "$jsmn_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "cannot read the jsmn version from core/third_party/jsmn/VERSION ('$jsmn_version')"

tmp=$(mktemp "$sbom.XXXXXX")
trap 'rm -f "$tmp"' EXIT
jq --arg agent "$agent_version" --arg mbedtls "$mbedtls_version" --arg jsmn "$jsmn_version" '
  def license($id): [{license: {id: $id}}];
  [
    {
      "bom-ref": "firmline-sdk/firmline-agent",
      type: "application",
      name: "firmline-agent",
      version: $agent,
      licenses: license("Apache-2.0"),
      purl: "pkg:github/bricktechnologies/firmline-sdk@v\($agent)"
    },
    {
      "bom-ref": "firmline-sdk/mbedtls",
      type: "library",
      name: "mbedtls",
      version: $mbedtls,
      licenses: license("Apache-2.0"),
      purl: "pkg:github/Mbed-TLS/mbedtls@v\($mbedtls)",
      cpe: "cpe:2.3:a:arm:mbed_tls:\($mbedtls):*:*:*:*:*:*:*"
    },
    {
      "bom-ref": "firmline-sdk/jsmn",
      type: "library",
      name: "jsmn",
      version: $jsmn,
      licenses: license("MIT"),
      purl: "pkg:github/zserge/jsmn@v\($jsmn)"
    }
  ] as $ours
  | ($ours | map(."bom-ref")) as $refs
  | if type != "object" or .bomFormat != "CycloneDX" then error("not a CycloneDX JSON document") else . end
  | .components = ([(.components // [])[] | select((."bom-ref" // "") as $r | $refs | any(. == $r) | not)] + $ours)
' "$sbom" >"$tmp" || die "$sbom cannot be read as CycloneDX JSON"
mv "$tmp" "$sbom"
trap - EXIT
echo "sbom-components: $sbom: firmline-agent $agent_version, mbedtls $mbedtls_version, jsmn $jsmn_version"
