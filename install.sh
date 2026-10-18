#!/bin/sh
# Install nethound into ~/.local/bin:
#   curl -fsSL https://github.com/michelsalib/nethound/releases/latest/download/install.sh | sh
#
# NETHOUND_INSTALL_DIR  where to put `nethound` (default ~/.local/bin)
# NETHOUND_VERSION      a version such as 0.2.1 (default: the latest release)
# NETHOUND_BASE_URL     where nethound.js and SHA256SUMS are downloaded from: https://, or file:// (mirrors, tests)
# NETHOUND_BINARY=1     install the standalone binary even when Node or Bun is there
# NETHOUND_NO_COMPLETION=1  don't install shell completion
#
# nethound is one small JavaScript file that runs on Node >= 20 or Bun. Without either, install.sh
# installs the standalone binary instead (Linux and macOS, x64 and arm64), which needs nothing.
# On Windows, use install.ps1.
set -eu

# Everything runs from main, called on the last line: if the download is cut short,
# sh reads a function that never closes and runs nothing.
main() {
say() { printf '%s\n' "$*"; }
fail() { printf 'nethound install: %s\n' "$*" >&2; exit 1; }

repo=michelsalib/nethound
dir=${NETHOUND_INSTALL_DIR:-$HOME/.local/bin}
version=${NETHOUND_VERSION:-latest}
version=${version#v}
case $version in
  latest) ;;
  *) printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
    fail "NETHOUND_VERSION must look like 0.2.1, not $version" ;;
esac
if [ -n "${NETHOUND_BASE_URL:-}" ]; then
  base=$NETHOUND_BASE_URL
elif [ "$version" = latest ]; then
  base=https://github.com/$repo/releases/latest/download
else
  base=https://github.com/$repo/releases/download/v$version
fi

# https only (file: for local mirrors and tests), redirects included
case $base in
  https://* | file://*) ;;
  *) fail "NETHOUND_BASE_URL must start with https://, not $base" ;;
esac

# the runtime: Node >= 20 first, then Bun, else the binary
if [ -n "${NETHOUND_BINARY:-}" ]; then
  runtime=binary
elif command -v node >/dev/null 2>&1 &&
  node -e 'process.exit(+process.versions.node.split(".")[0] >= 20 ? 0 : 1)' 2>/dev/null; then
  runtime=node
elif command -v bun >/dev/null 2>&1; then
  runtime=bun
else
  runtime=binary
fi

file=nethound.js
if [ "$runtime" = binary ]; then
  case $(uname -s) in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) fail "no nethound binary for $(uname -s); install Node >= 20 or Bun (https://nodejs.org, https://bun.sh), or on Windows use install.ps1" ;;
  esac
  case $(uname -m) in
    x86_64 | amd64) arch=x64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "no nethound binary for $(uname -m); install Node >= 20 or Bun (https://nodejs.org, https://bun.sh)" ;;
  esac
  file=nethound-$os-$arch
fi

if command -v curl >/dev/null 2>&1; then
  download() { curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  download() { wget --secure-protocol=TLSv1_2 -qO "$2" "$1"; }
else
  fail "needs curl or wget to download nethound"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "needs sha256sum or shasum to check the download"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

download "$base/$file" "$tmp/$file" || fail "could not download $base/$file"
download "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download $base/SHA256SUMS"
expected=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || fail "SHA256SUMS has no entry for $file"
[ "$(sha256 "$tmp/$file")" = "$expected" ] || fail "checksum mismatch for $file; nothing was installed"

# the build starts with `#!/usr/bin/env node`
if [ "$runtime" = bun ]; then
  sed '1s|.*|#!/usr/bin/env bun|' "$tmp/$file" >"$tmp/nethound"
else
  cp "$tmp/$file" "$tmp/nethound"
fi
chmod 755 "$tmp/nethound"

mkdir -p "$dir"
# copy next to the target, then rename: a running nethound is never left half-written
cp "$tmp/nethound" "$dir/.nethound.new"
mv -f "$dir/.nethound.new" "$dir/nethound"

if [ "$runtime" = binary ]; then how="standalone binary"; else how="runs on $runtime"; fi
say "installed nethound $("$dir/nethound" --version) in $dir ($how)"
say "to see the processes of other users too: sudo $dir/nethound"

# completion goes where shells load it by themselves; startup files are never edited
if [ -z "${NETHOUND_NO_COMPLETION:-}" ]; then
  data=${XDG_DATA_HOME:-$HOME/.local/share}
  config=${XDG_CONFIG_HOME:-$HOME/.config}
  mkdir -p "$data/bash-completion/completions"
  "$dir/nethound" completion bash >"$data/bash-completion/completions/nethound"
  bash_completion=
  for f in /usr/share/bash-completion/bash_completion /etc/bash_completion \
    /opt/homebrew/etc/profile.d/bash_completion.sh /usr/local/etc/profile.d/bash_completion.sh; do
    if [ -r "$f" ]; then bash_completion=$f; break; fi
  done
  if [ -n "$bash_completion" ]; then
    say "bash completion: installed (new shells)"
  else
    say "bash completion: bash-completion isn't installed; add this to ~/.bashrc instead:"
    say "  eval \"\$(nethound completion bash)\""
  fi
  if command -v fish >/dev/null 2>&1; then
    mkdir -p "$config/fish/completions"
    "$dir/nethound" completion fish >"$config/fish/completions/nethound.fish"
    say "fish completion: installed"
  fi
  if command -v zsh >/dev/null 2>&1; then
    say "zsh completion: add this to ~/.zshrc, after compinit:"
    say "  eval \"\$(nethound completion zsh)\""
  fi
fi

case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "$dir is not in your PATH; add it in your shell's startup file:"
     say "  export PATH=\"$dir:\$PATH\"" ;;
esac
}

main "$@"
