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

# Helper: is $1 >= $2 using version sort?
version_ge() {
    [ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

# Extract all .tar.gz download URLs from the release JSON
ALL_URLS=$(echo "$RELEASE_DATA" \
    | grep -o '"browser_download_url": *"[^"]*\.tar\.gz"' \
    | sed 's/"browser_download_url": *"//;s/"$//')

# Select the right tarball based on OS, architecture, and local system version.
# Release tarballs are named:
#   Linux:  wif-bunker-VERSION-linux-ARCH-glibcVER.tar.gz
#   macOS:  wif-bunker-VERSION-macos-arm64-OSVER.tar.gz
DOWNLOAD_URL=""
if [ "$OS" = "linux" ]; then
    # Detect local glibc version
    LOCAL_GLIBC=$(ldd --version 2>&1 | head -n1 | awk '{print $NF}')
    if [ -z "$LOCAL_GLIBC" ]; then
        echo "Error: Could not detect glibc version"
        exit 1
    fi
    echo "Local glibc: $LOCAL_GLIBC"

    # Find all builds for our architecture, pick highest glibc <= local
    ASSET_PATTERN="linux-${ARCH}-glibc"
    DOWNLOAD_URL=$(echo "$ALL_URLS" \
        | grep "$ASSET_PATTERN" \
        | while read -r url; do
            build_ver=$(echo "$url" | grep -o "glibc[0-9.]*" | sed 's/glibc//')
            if version_ge "$LOCAL_GLIBC" "$build_ver"; then
                echo "$build_ver $url"
            fi
        done \
        | sort -t' ' -k1 -V \
        | tail -n1 \
        | cut -d' ' -f2-)

elif [ "$OS" = "macos" ]; then
    # Detect local macOS major version
    LOCAL_MACOS=$(sw_vers -productVersion | cut -d. -f1)
    echo "Local macOS version: $LOCAL_MACOS"

    # Find all macOS builds, pick highest OS version <= local
    ASSET_PATTERN="macos-arm64-"
    DOWNLOAD_URL=$(echo "$ALL_URLS" \
        | grep "$ASSET_PATTERN" \
        | while read -r url; do
            build_ver=$(echo "$url" | grep -o "macos-arm64-[0-9]*" | sed 's/macos-arm64-//')
            if version_ge "$LOCAL_MACOS" "$build_ver"; then
                echo "$build_ver $url"
            fi
        done \
        | sort -t' ' -k1 -V \
        | tail -n1 \
        | cut -d' ' -f2-)
fi

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Error: Could not find a compatible ${OS}/${ARCH} tarball in release $ACTUAL_VERSION"
    if [ "$OS" = "linux" ]; then
        echo "Local glibc $LOCAL_GLIBC may be older than all available builds."
    elif [ "$OS" = "macos" ]; then
        echo "Local macOS $LOCAL_MACOS may be older than all available builds."
    fi
    echo "Available assets:"
    echo "$ALL_URLS"
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
