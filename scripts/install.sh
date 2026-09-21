#!/bin/bash
#
# deed - one-line installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.sh | bash
#
# Downloads the release build for this machine, verifies it against the SHA-256
# published beside it, and installs it into ~/.local/bin. No root, nothing
# outside your home directory, and nothing is installed that did not verify.
#
# One script for both systems rather than two, because deed publishes the same
# thing four times: a tar.gz holding one static binary, named for the platform.
# Two scripts would share every line that matters and drift in the ones that do
# not.
#
# Read it first if you would rather. Building from source is four lines and is
# documented at https://github.com/zig-nostr/deed#build
#
# This file is deliberately pure ASCII. macOS ships bash 3.2, where a multibyte
# character sitting next to a $variable under `set -u` aborts the script, and an
# installer that dies on its own punctuation is a bad first impression. CI fails
# on any byte above 0x7F in here.
#
set -euo pipefail

repo="zig-nostr/deed"
prefix="$HOME/.local"
version=""
archive=""

# Script scope, not a function's. The EXIT trap runs after the function that
# made the directory has returned, and a `local` is gone by then: under `set -u`
# the cleanup would die on its own variable at the end of a successful install.
workdir=""
# `return 0` on purpose. Without it the trap's last command is a failed test on
# a run that never made a temp directory, and bash exits with THAT, so `--help`
# would report failure.
cleanup() {
  [ -n "$workdir" ] && rm -rf "$workdir"
  return 0
}
trap cleanup EXIT

say()  { printf '==> %s\n' "$1"; }
warn() { printf 'note: %s\n' "$1"; }
die()  { printf 'error: %s\n' "$1" >&2; exit 1; }

usage() {
  cat <<'USAGE'
deed installer

  install.sh [options]

Options:
  --prefix <dir>     install into <dir>/bin (default: ~/.local)
  --version <vX.Y.Z> install this release instead of the latest
  --archive <file>   install from a tarball already on disk, skipping the
                     download. Its .sha256 is still required, beside it.
  -h, --help         this text

Installs deed into <prefix>/bin. Nothing needs root.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)  [ $# -ge 2 ] || die "--prefix needs a directory"; prefix="$2"; shift 2 ;;
    --version) [ $# -ge 2 ] || die "--version needs a tag"; version="$2"; shift 2 ;;
    --archive) [ $# -ge 2 ] || die "--archive needs a file"; archive="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option '$1'. Run with --help." ;;
  esac
done

# Which build this machine wants.
#
# `uname -m` answers with several spellings for the same two architectures, so
# they are folded rather than matched one at a time. A machine this does not
# recognise is told so by name, because "unsupported" without the name it
# reported is not something anybody can act on.
detect() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os" in
    darwin) os=macos ;;
    linux)  os=linux ;;
    *) die "deed publishes macOS and Linux builds. This machine reports '$os'." ;;
  esac

  case "$arch" in
    x86_64|amd64)  arch=x86_64 ;;
    arm64|aarch64) arch=aarch64 ;;
    *) die "no deed build for '$arch'. The published builds are x86_64 and aarch64." ;;
  esac

  printf '%s-%s\n' "$os" "$arch"
}

# sha256sum on Linux, shasum -a 256 on macOS. Both print the digest first.
digest_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "neither sha256sum nor shasum is on this machine, so the download cannot be verified. Not installing it."
  fi
}

# The tag of the newest release.
#
# The status code comes back on its own line, so a rate limit and a dead network
# stop being the same unhelpful message.
latest_tag() {
  local api resp code json tag
  api="https://api.github.com/repos/$repo/releases/latest"
  resp="$(curl -sSL -w '\n%{http_code}' "$api")" ||
    die "could not reach GitHub. Check your connection and try again."
  code="$(printf '%s' "$resp" | tail -1)"
  json="$(printf '%s' "$resp" | sed '$d')"
  case "$code" in
    200) ;;
    403) die "GitHub rate-limited this machine. Wait a few minutes, or pass --version." ;;
    404) die "no published release found for $repo." ;;
    *)   die "GitHub answered $code." ;;
  esac
  # `|| true` because grep exits 1 on no match, which under `set -e` would kill
  # the assignment before the emptiness check below could give a better message.
  tag="$(printf '%s' "$json" | grep -o '"tag_name":[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
  [ -n "$tag" ] || die "could not read the release tag from GitHub's answer."
  printf '%s\n' "$tag"
}

# Verifies a tarball against the digest published beside it.
#
# The digest is read from the `.sha256` file that sits next to the artifact, not
# out of an API response. Nothing is chosen by position, so there is no list to
# pick the wrong element out of.
verify() {
  local file="$1" sidecar="$2" want got
  want="$(awk '{print $1}' "$sidecar")"
  # An empty expected digest compares equal to an empty computed one, and the
  # check then reports success over nothing at all. Both sides have to exist
  # before either is trusted.
  [ -n "$want" ] || die "the published SHA-256 for $(basename "$file") is empty. Not installing it."
  got="$(digest_of "$file")"
  [ -n "$got" ] || die "could not compute the SHA-256 of the download. Not installing it."
  [ "$want" = "$got" ] || die "the download does not match its published SHA-256. Not installing it."
}

main() {
  local platform tag asset url bindir
  platform="$(detect)"

  workdir="$(mktemp -d)"
  [ -n "$workdir" ] || die "could not make a temporary directory."

  if [ -n "$archive" ]; then
    [ -f "$archive" ] || die "no such file: $archive"
    [ -f "$archive.sha256" ] || die "$archive.sha256 is missing. Download it beside the tarball."
    say "Verifying $(basename "$archive")..."
    verify "$archive" "$archive.sha256"
    cp "$archive" "$workdir/deed.tar.gz"
  else
    tag="${version:-$(latest_tag)}"
    case "$tag" in
      v*) ;;
      *) die "a release tag looks like v0.1.0. Got '$tag'." ;;
    esac
    asset="deed-${tag#v}-$platform.tar.gz"
    url="https://github.com/$repo/releases/download/$tag/$asset"

    say "Downloading $asset..."
    curl -fSL --progress-bar -o "$workdir/deed.tar.gz" "$url" ||
      die "download failed. There may be no $platform build for $tag."

    # Required, not best-effort. A verification step that any transient failure
    # switches off is not a verification step, and every published release has
    # one of these beside every artifact.
    curl -fsSL --retry 2 --retry-all-errors -o "$workdir/deed.tar.gz.sha256" "$url.sha256" 2>/dev/null ||
      die "could not fetch the published SHA-256 for $asset, so the download cannot be verified. Not installing it."

    say "Verifying..."
    verify "$workdir/deed.tar.gz" "$workdir/deed.tar.gz.sha256"
  fi
  say "SHA-256 verified."

  tar -C "$workdir" -xzf "$workdir/deed.tar.gz" 2>/dev/null ||
    die "the archive could not be unpacked. The download may be incomplete."
  [ -f "$workdir/deed" ] || die "the archive did not contain a deed binary."

  bindir="$prefix/bin"
  say "Installing into $bindir..."
  mkdir -p "$bindir" || die "could not create $bindir."
  install -m 0755 "$workdir/deed" "$bindir/deed" ||
    die "could not write to $bindir. Pass --prefix to install somewhere you own."

  # The macOS builds are ad-hoc signed and not notarized. A copy that came
  # through a browser carries a quarantine flag; one fetched by curl usually
  # does not, but clearing it costs nothing and saves a confusing refusal.
  if [ "${platform%%-*}" = "macos" ] && command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$bindir/deed" >/dev/null 2>&1 || true
  fi

  # Run the thing that was just installed. An install that reports success
  # without ever executing the binary is how a wrong-architecture download, or
  # an archive holding only a licence, gets called a success.
  local reported
  reported="$("$bindir/deed" version 2>/dev/null)" ||
    die "deed was installed to $bindir but will not run on this machine."
  say "Installed $reported to $bindir/deed"

  case ":$PATH:" in
    *":$bindir:"*) ;;
    *) warn "$bindir is not on your PATH. Add it to your shell profile:
       export PATH=\"$bindir:\$PATH\"" ;;
  esac
}

main
