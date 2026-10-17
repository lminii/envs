#!/bin/sh
# Prints the Homebrew formula for one release.
# Usage: scripts/homebrew-formula.sh <version without v> <path to SHA256SUMS>
set -eu

version="$1"
sums="$2"

sum() {
  value=$(awk -v name="envs-$1" '$2 == name { print $1 }' "$sums")
  if [ -z "$value" ]; then
    echo "no checksum for envs-$1 in $sums" >&2
    exit 1
  fi
  echo "$value"
}

url="https://github.com/lminii/envs/releases/download/v$version"

cat <<FORMULA
class Envs < Formula
  desc "Sync encrypted development secrets through a private git repository"
  homepage "https://github.com/lminii/envs"
  license "MIT"

  uses_from_macos "git"

  on_macos do
    on_arm do
      url "$url/envs-darwin-arm64"
      sha256 "$(sum darwin-arm64)"
    end
    on_intel do
      url "$url/envs-darwin-amd64"
      sha256 "$(sum darwin-amd64)"
    end
  end

  on_linux do
    on_arm do
      url "$url/envs-linux-arm64"
      sha256 "$(sum linux-arm64)"
    end
    on_intel do
      url "$url/envs-linux-amd64"
      sha256 "$(sum linux-amd64)"
    end
  end

  def install
    bin.install Dir["envs-*"].first => "envs"
  end

  test do
    assert_match "envs syncs encrypted development secrets", shell_output("#{bin}/envs help")
  end
end
FORMULA
