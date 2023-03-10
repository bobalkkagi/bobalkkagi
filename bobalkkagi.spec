# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_dynamic_libs

dlls = collect_dynamic_libs("capstone") + collect_dynamic_libs("unicorn") + collect_dynamic_libs("fire")+collect_dynamic_libs("distorm3")
resource_files = [('bobalkkagi/', 'bobalkkagi')]
block_cipher = None


a = Analysis(
    ['bobalkkagi\\__main__.py'],
    pathex=[],
    binaries=dlls,
    datas=resource_files,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    a.datas,[],
    name='bobalkkagi',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
