"""Package only source, instructions and reports; never bundle the dataset."""
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED

root=Path(__file__).resolve().parents[1]
required=['README.md','code/main.py','code/evaluation/evaluation_report.md','code/evaluation/usage_report.md']
for name in required:
    if not (root/name).is_file(): raise SystemExit('Missing required artifact: '+name)
allowed={'.py','.ps1','.md','.txt'}
files=[root/'README.md']
for path in (root/'code').rglob('*'):
    if not path.is_file() or any(p in ('__pycache__','.venv','venv','node_modules','.git') for p in path.parts): continue
    if path.suffix.lower() in allowed: files.append(path)
with ZipFile(root/'code.zip','w',ZIP_DEFLATED) as z:
    for path in sorted(files): z.write(path,path.relative_to(root).as_posix())
with ZipFile(root/'code.zip') as z:
    assert z.testzip() is None
    assert not any(name.startswith('dataset/') for name in z.namelist())
    print('Packaged',len(z.namelist()),'files in',root/'code.zip')
