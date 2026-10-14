# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\Atharva\\Desktop\\project x\\Secure-Token-Based-Malpractice-Prevention\\tokens\\monitor.py'],
    pathex=['C:\\Users\\Atharva\\Desktop\\project x\\Secure-Token-Based-Malpractice-Prevention'],
    binaries=[],
    datas=[],
    hiddenimports=['shared', 'shared.crypto_utils', 'wmi', 'pythoncom', 'win32com'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='monitor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
