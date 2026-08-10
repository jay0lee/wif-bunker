#!/usr/bin/env bash
# WIF Bunker Installer script
# Modeled after GAM's gam-install.sh

set -e

VERSION="latest"
INSTALL_DIR="$HOME/bin/wif-bunker"
UPGRADE_ONLY=0

show_help() {
    echo "WIF Bunker Installer"
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -v VERSION   Specify version to install (e.g. v1.0.0). Default: latest"
    echo "  -d DIR       Specify installation directory. Default: $HOME/bin/wif-bunker"
    echo "  -l           Upgrade only (skip PATH setup)"
    echo "  -h           Show this help"
}

while getopts "v:d:lh" opt; do
    case "$opt" in
        v) VERSION="$OPTARG" ;;
        d) INSTALL_DIR="$OPTARG" ;;
        l) UPGRADE_ONLY=1 ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Detect OS
OS_NAME=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS_NAME" in
    linux) OS="linux" ;;
    darwin) OS="macos" ;;
    *) echo "Error: Unsupported OS $OS_NAME"; exit 1 ;;
esac

# Detect Architecture
ARCH_NAME=$(uname -m)
case "$ARCH_NAME" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "Error: Unsupported architecture $ARCH_NAME"; exit 1 ;;
esac

echo "Detected OS: $OS, Architecture: $ARCH"

# Determine API URL
if [ "$VERSION" = "latest" ]; then
    API_URL="https://api.github.com/repos/jay0lee/wif-bunker/releases/latest"
else
    API_URL="https://api.github.com/repos/jay0lee/wif-bunker/releases/tags/$VERSION"
fi

# Fetch release info
echo "Fetching release info from GitHub..."
CURL_OPTS=("-s" "-f")
if [ -n "$GITHUB_TOKEN" ]; then
    CURL_OPTS+=("-H" "Authorization: token $GITHUB_TOKEN")
fi

RELEASE_DATA=$(curl "${CURL_OPTS[@]}" "$API_URL" || { echo "Failed to fetch release info"; exit 1; })

# Determine tag name in case 'latest' was requested
ACTUAL_VERSION=$(echo "$RELEASE_DATA" | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$ACTUAL_VERSION" ]; then
    echo "Error: Could not determine release version."
    exit 1
fi
# Strip 'v' prefix if we want to match the tarball name explicitly, assuming naming is wif-bunker-1.0.0-...
CLEAN_VERSION="${ACTUAL_VERSION#v}"

# Build a grep pattern to find the right tarball from release assets.
# Release tarballs are named: wif-bunker-VERSION-{runner}.tar.gz
# where {runner} is e.g. macos-26, ubuntu-24.04, ubuntu-24.04-arm.
# We pick the highest-versioned runner matching our OS+arch.
case "${OS}-${ARCH}" in
    macos-arm64)   ASSET_PATTERN="macos-" ;;
    linux-x86_64)  ASSET_PATTERN="ubuntu-[0-9]" ;;     # matches ubuntu-NN.NN but NOT ubuntu-NN.NN-arm
    linux-arm64)   ASSET_PATTERN="ubuntu-.*-arm" ;;
    *)             echo "Error: No release artifact for ${OS}-${ARCH}"; exit 1 ;;
esac

# Extract all .tar.gz download URLs from the release JSON
DOWNLOAD_URL=$(echo "$RELEASE_DATA" \
    | grep -o '"browser_download_url": *"[^"]*\.tar\.gz"' \
    | sed 's/"browser_download_url": *"//;s/"$//' \
    | grep "$ASSET_PATTERN" \
    | sort -V \
    | tail -n 1)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Error: Could not find a ${OS}/${ARCH} tarball in release $ACTUAL_VERSION"
    echo "Available assets:"
    echo "$RELEASE_DATA" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/"browser_download_url": *"//;s/"$//'
    exit 1
fi

TARBALL=$(basename "$DOWNLOAD_URL")

echo "Downloading $TARBALL..."
curl -L -f -o "$TARBALL" "$DOWNLOAD_URL" || { echo "Download failed"; exit 1; }

echo "Extracting to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
tar -xzf "$TARBALL" -C "$INSTALL_DIR" --strip-components=1

rm "$TARBALL"

if [ $UPGRADE_ONLY -eq 0 ]; then
    # Setup PATH
    SHELL_PROFILE=""
    if [[ "$SHELL" == *zsh* ]]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [[ "$SHELL" == *bash* ]]; then
        if [ "$OS" = "macos" ] && [ -f "$HOME/.bash_profile" ]; then
            SHELL_PROFILE="$HOME/.bash_profile"
        else
            SHELL_PROFILE="$HOME/.bashrc"
        fi
    else
        SHELL_PROFILE="$HOME/.profile"
    fi

    if [ -n "$SHELL_PROFILE" ]; then
        if ! grep -q "$INSTALL_DIR" "$SHELL_PROFILE"; then
            echo "" >> "$SHELL_PROFILE"
            echo "# WIF Bunker PATH" >> "$SHELL_PROFILE"
            echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$SHELL_PROFILE"
            echo "Added $INSTALL_DIR to PATH in $SHELL_PROFILE"
            echo "Please run 'source $SHELL_PROFILE' or restart your terminal."
        else
            echo "$INSTALL_DIR is already in $SHELL_PROFILE"
        fi
    fi
fi

echo "WIF Bunker installation completed successfully!"
