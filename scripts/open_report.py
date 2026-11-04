"""Open a generated TXT in the user's existing desktop text viewer."""
import os
from pathlib import Path
import shutil
import subprocess


def open_report(path):
    path=Path(path).resolve(strict=True)
    if not path.is_file() or path.suffix.lower()!='.txt':raise ValueError('Select a generated TXT report')
    command=None
    notepad=shutil.which('notepad.exe')
    if notepad and shutil.which('wslpath'):
        converted=subprocess.run(['wslpath','-w',str(path)],capture_output=True,text=True,timeout=10,check=True).stdout.strip()
        command=[notepad,converted]
    elif shutil.which('wslview'):command=[shutil.which('wslview'),str(path)]
    elif (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')) and shutil.which('xdg-open'):
        command=[shutil.which('xdg-open'),str(path)]
    if command is None:return {'status':'UNAVAILABLE','path':str(path),'detail':'No desktop text viewer; display the generated file in the TUI'}
    subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    return {'status':'OPEN_REQUESTED','path':str(path)}
