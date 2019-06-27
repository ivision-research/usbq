from itertools import chain
from pathlib import Path

from doitpy.pyflakes import Pyflakes


def task_pyflakes():
    'Run pyflakes'

    flaker = Pyflakes(exclude_patterns=['__init__.py'])
    yield flaker.tasks('usbq/**/*.py')
    yield flaker.tasks('dodo.py')
    yield flaker.tasks('test/**/*.py')


def task_isort():
    'Run isort to sort imports'

    for f in chain.from_iterable(
        [Path('test').glob('**/*.py'), Path('usbq').glob('**/*.py'), [Path('dodo.py')]]
    ):
        if '__init__.py' in str(f):
            continue
        yield {
            'name': f,
            'actions': [f'isort {f}'],
            'file_dep': [f],
            'task_dep': [f'pyflakes:{f}'],
        }
