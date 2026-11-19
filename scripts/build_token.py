import PyInstaller.__main__
import os
import sys

# Project root (one level up from this script)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Path to the monitor entry-point
monitor_script = os.path.join(project_root, 'tokens', 'monitor.py')

# ── Common args ───────────────────────────────────────────────────────────────
args = [
    monitor_script,
    '--onefile',
    '--name=monitor',
    f'--paths={project_root}',
    '--hidden-import=shared',
    '--hidden-import=shared.crypto_utils',
    '--log-level=WARN',
    '--clean',
    '--distpath', os.path.join(project_root, 'dist'),
    '--workpath', os.path.join(project_root, 'build'),
]

# ── Platform-specific args ────────────────────────────────────────────────────
if sys.platform == "win32":
    args += [
        '--hidden-import=wmi',
        '--hidden-import=pythoncom',
        '--hidden-import=win32com',
        '--noconsole',   # Hide console window on Windows
    ]
elif sys.platform == "linux":
    args += [
        '--hidden-import=pyudev',
        '--hidden-import=evdev',
        # No --noconsole on Linux; use --windowed only if running a GUI display server
    ]

platform_label = "Windows (.exe)" if sys.platform == "win32" else "Linux (ELF binary)"
print(f"Building monitor for {platform_label}")
print(f"  Source : {monitor_script}")
print(f"  Output : {os.path.join(project_root, 'dist')}")
print()

PyInstaller.__main__.run(args)

print()
print("Build complete.")
if sys.platform == "win32":
    print("  Artifact: dist/monitor.exe")
else:
    print("  Artifact: dist/monitor")
    print("  Run with: sudo dist/monitor  (or add your user to the 'input' group first)")
