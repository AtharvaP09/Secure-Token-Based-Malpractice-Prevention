import PyInstaller.__main__
import os
import shutil

# Ensure shared is available
if not os.path.exists("tokens/shared"):
    shutil.copytree("shared", "tokens/shared")

PyInstaller.__main__.run([
    'tokens/monitor.py',
    '--onefile',
    '--name=ExamToken',
    '--add-data=tokens/shared;shared', # Adjust based on how we import
    '--hidden-import=win32timezone',
    '--clean',
    '--distpath=dist',
    '--workpath=build',
    '--specpath=.'
])

print("Build Complete. Executable is in dist/ExamToken.exe")
