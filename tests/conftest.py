from __future__ import annotations

import copy
from pathlib import Path

import pytest

from haproxy_ui.importer import parse_cfg

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def original_cfg() -> str:
    return (FIXTURES / "haproxy.cfg").read_text()


@pytest.fixture
def imported(original_cfg):
    return parse_cfg(original_cfg, read_dir=FIXTURES)


@pytest.fixture
def state(imported) -> dict:
    return copy.deepcopy(imported.state)
