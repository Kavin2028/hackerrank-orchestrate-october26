"""Verify a new extraction with fresh OCR and participant data kept outside ZIP."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile

ROOT=Path(__file__).resolve().parents[2]

def main():
    expected=(ROOT/'output.csv').read_bytes()
    with ZipFile(ROOT/'code.zip') as archive:
        if archive.testzip() is not None: raise ValueError('Archive CRC failure')
        names=archive.namelist()
        for name in ('README.md','code/main.py','code/requirements.txt','evaluation/evaluation_report.md','evaluation/usage_report.md'):
            if name not in names: raise ValueError('Missing archive member: '+name)
        for name in names:
            path=Path(name)
            if path.is_absolute() or '..' in path.parts or ':' in name: raise ValueError('Unsafe archive member')
            if any(part in ('dataset','__pycache__','.venv','venv','node_modules','.git') for part in path.parts):
                raise ValueError('Excluded directory in archive: '+name)
            if path.suffix.lower() in ('.zip','.env','.pem','.key') or path.name.startswith('.env'):
                raise ValueError('Excluded file in archive: '+name)
        # TemporaryDirectory owns this exact newly allocated directory; no
        # existing checkout or user directory is removed by this verifier.
        with tempfile.TemporaryDirectory(prefix='deletion-audit-package-') as folder:
            clean=Path(folder).resolve()
            archive.extractall(clean)
            shutil.copytree(ROOT/'dataset',clean/'dataset')
            proc=subprocess.run([sys.executable,str(clean/'code/main.py')],cwd=clean,capture_output=True,text=True)
            if proc.returncode: raise RuntimeError(proc.stdout+'\n'+proc.stderr)
            actual=(clean/'output.csv').read_bytes()
            if actual!=expected: raise ValueError('Clean extraction produced a different output')
            sys.path.insert(0,str(clean/'code'))
            # Validate through the extracted evaluator, not a cached import.
            import importlib.util
            spec=importlib.util.spec_from_file_location('clean_evaluator',clean/'code/evaluation/main.py')
            evaluator=importlib.util.module_from_spec(spec); spec.loader.exec_module(evaluator)
            from main import rows
            errors,review=evaluator.validate(rows(clean/'output.csv'),rows(clean/'dataset/deletion_requests.csv'),clean/'dataset')
            if errors: raise ValueError(str(errors))
            print(json.dumps({'archive_files':len(names),'rows':len(rows(clean/'output.csv')),'fresh_ocr_images':len(list((clean/'tmp/ocr').glob('*.txt'))),'output_sha256':hashlib.sha256(actual).hexdigest(),'byte_identical':True,'validation_errors':errors,'empty_authorized_plans':review},indent=2))

if __name__=='__main__': main()
