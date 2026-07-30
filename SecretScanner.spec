# PyInstaller spec — used for the Windows build (see .github/workflows/release.yml).
# macOS ships via py2app (setup.py), which produces a better .app bundle.

block_cipher = None

a = Analysis(
    ["macapp/launch.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=["secret_scanner"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest", "setuptools", "pip"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="SecretScanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
)
