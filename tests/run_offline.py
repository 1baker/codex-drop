"""Run only the default synthetic suites, without optional live integrations."""
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    if shutil.which('node') is None:
        raise SystemExit('Node.js is required for the offline frontend checks.')
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    for key in ('CODEX_DROP_SSH', 'CODEX_DROP_PS', 'CODEX_DROP_NATIVE',
                'CODEX_SSH_INTEGRATION', 'CODEX_SSH_NATIVE'):
        env.pop(key, None)
    for name in ('test_codex_drop.py', 'test_codex_drop_web.py'):
        result = subprocess.run([sys.executable, '-I', '-B', str(root / 'tests' / name)],
                                cwd=root, env=env, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
