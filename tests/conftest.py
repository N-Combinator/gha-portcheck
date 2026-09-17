from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def make_repo(tmp_path):
    """Build a throwaway repository containing the given fixture workflows.

    ``make_repo("a-runs-on.yml")`` copies the fixture into ``.github/workflows``;
    ``make_repo("x.yml", directory=".gitea/workflows")`` puts it elsewhere.
    """

    def _make(*fixtures: str, directory: str = ".github/workflows") -> Path:
        repo = tmp_path / "repo"
        target = repo / directory
        target.mkdir(parents=True, exist_ok=True)
        for name in fixtures:
            shutil.copy(FIXTURES / name, target / name)
        repo.mkdir(exist_ok=True)
        return repo

    return _make
