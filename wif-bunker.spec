# -*- mode: python ; coding: utf-8 -*-
"""WIF Bunker PyInstaller spec — single-directory build."""

block_cipher = None

# Hidden imports required by google-auth and related libraries.
# These are dynamically imported and PyInstaller can't detect them.
hiddenimports = [
    'google.auth',
    'google.auth.transport.requests',
    'google.auth.identity_pool',
    'google.auth.external_account',
    'google.auth.impersonated_credentials',
    'google.auth.transport._mtls_helper',
    'google.auth.transport._custom_tls_signer',
    'get_ecp',
]

a = Analysis(
    ['wif_bunker.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

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
    codesign_identity=None,
    entitlements_file=None,
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
