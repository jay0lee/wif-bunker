# -*- mode: python ; coding: utf-8 -*-
"""WIF Bunker PyInstaller spec — pure-Python single-directory build."""

import os
import sys
from PyInstaller.utils.hooks import copy_metadata

block_cipher = None

# ── Hidden imports ──
# Signer backends are imported lazily inside wif_bunker/signers.py.
hiddenimports = [
    'dpop_signer_yubikey',
    'dpop_signer_pkcs11',
    'dpop_signer_fido2_previewsign',
    'google.auth.dpop',
]
if sys.platform == 'win32':
    hiddenimports.append('dpop_signer_windows_certstore')
elif sys.platform == 'darwin':
    hiddenimports.append('dpop_signer_macos_secureenclave')
elif sys.platform.startswith('linux'):
    hiddenimports.append('dpop_signer_linux_tpm')

# ── Package metadata ──
datas = []
for pkg in ('google-auth', 'requests', 'cryptography', 'certifi', 'urllib3', 'charset-normalizer'):
    try:
        datas += copy_metadata(pkg, recursive=True)
    except Exception:
        pass

# ── Attestation root certificates ──
datas += [
    ('wif_bunker/attestation/roots/roots/*.pem', 'wif_bunker/attestation/roots/roots'),
    ('wif_bunker/attestation/roots/intermediates/*.pem', 'wif_bunker/attestation/roots/intermediates'),
    ('wif_bunker/attestation/roots/manually-managed/*.pem', 'wif_bunker/attestation/roots/manually-managed'),
    ('wif_bunker/attestation/roots/yubico/*.pem', 'wif_bunker/attestation/roots/yubico'),
]

# ── Excludes ──
excludes = [
    'tkinter',
    'unittest',
    'xmlrpc',
    'pydoc',
    'doctest',
    'test',
]

a = Analysis(
    ['wif_bunker/cli.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

version_file = 'version_info.txt' if os.path.exists('version_info.txt') else None
codesign_identity = os.environ.get('codesign_identity') or None
entitlements_file = 'packaging/macos/entitlements.plist' if os.path.exists('packaging/macos/entitlements.plist') else None

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='wif-bunker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=codesign_identity,
    entitlements_file=entitlements_file,
    version=version_file,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='wif-bunker',
    contents_directory='lib',
)
