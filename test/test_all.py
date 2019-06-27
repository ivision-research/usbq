import importlib
import re
from pathlib import Path

import pytest


def as_module(p):
    return re.sub('/', '.', re.sub(r'\.py', '', str(p)))


modules = [
    as_module(f) for f in Path('usbq').glob('**/*.py') if '__init__' not in str(f)
]


@pytest.mark.parametrize('mod_name', modules)
def test_all(mod_name):
    'Test that __all__ contains only names that are actually exported.'

    mod = importlib.import_module(mod_name)

    missing = set(
        n for n in getattr(mod, '__all__', []) if getattr(mod, n, None) is None
    )
    assert (
        len(missing) == 0
    ), f'{mod_name}: __all__ contains unresolved names: {", ".join(missing)}'
