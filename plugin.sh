#!/bin/sh
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
sys="$(uname -s)"
case "$sys" in
MINGW* | MSYS* | CYGWIN*) rel="x86_64-pc-windows-msvc/gray-email.exe" ;;
Darwin*)
    case "$(uname -m)" in
    arm64) rel="aarch64-apple-darwin/gray-email" ;;
    *) rel="x86_64-apple-darwin/gray-email" ;;
    esac ;;
*)
    case "$(uname -m)" in
    aarch64 | arm64) rel="aarch64-unknown-linux-musl/gray-email" ;;
    *) rel="x86_64-unknown-linux-musl/gray-email" ;;
    esac ;;
esac
if [ -x "$here/$rel" ]; then exec "$here/$rel" "$@"; fi
for cand in "$here/target/release/gray-email.exe" "$here/target/release/gray-email" "$here/target/debug/gray-email.exe" "$here/target/debug/gray-email"; do
    if [ -x "$cand" ]; then exec "$cand" "$@"; fi
done
echo "gray-email binary not found in $here" >&2
exit 1
