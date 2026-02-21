import PyInstaller.__main__
import os
import sys

# Get the project root directory
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Path to monitor.py
monitor_script = os.path.join(project_root, 'tokens', 'monitor.py')

# Args for PyInstaller
args = [
    monitor_script,
    '--onefile',
    '--name=monitor',
    f'--paths={project_root}',
    '--hidden-import=shared',
    '--hidden-import=shared.crypto_utils',
    # Add other hidden imports if needed (e.g. win32com for WMI if we add it)
    '--log-level=WARN',
    '--clean',
    '--distpath', os.path.join(project_root, 'dist'),
    '--workpath', os.path.join(project_root, 'build'),
    '--noconsole' # Removed the console to prevent terminal popup
]

print(f"Building monitor.exe from {monitor_script}...")
print(f"Project root: {project_root}")

PyInstaller.__main__.run(args)

print("Build complete. Executable should be in 'dist' folder.")
