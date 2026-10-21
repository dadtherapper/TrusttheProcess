# Build from the repository root: python -m PyInstaller packaging/TrustTheProcess.spec
from pathlib import Path

root = Path(SPECPATH).parent
a = Analysis([str(root / 'packaging' / 'launch.py')], pathex=[str(root)],
             binaries=[], datas=[], hiddenimports=[], hookspath=[], hooksconfig={},
             runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='TrustTheProcess',
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
          console=False, disable_windowed_traceback=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='TrustTheProcess')

