#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os
from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add options to the pytest command line."""
    parser.addoption(
        "--charm_path", action="store", default=None, help="Path to the charm under test"
    )


@pytest.fixture(scope="session")
def charm(request: pytest.FixtureRequest) -> Path:
    """Return the path of the charm under test.

    Reads from the --charm_path CLI option or the CHARM_PATH environment
    variable, or finds a .charm file in the current working directory.
    """
    charm_path = request.config.getoption("--charm_path") or os.environ.get("CHARM_PATH")
    if not charm_path:
        charm_dir = Path()
        charms = list(charm_dir.glob("*.charm"))
        assert charms, f"No charms were found in {charm_dir.absolute()}"
        assert len(charms) == 1, f"Found more than one charm: {charms}"
        charm_path = str(charms[0])
    path = Path(charm_path).resolve()
    assert path.is_file(), f"{path} is not a file"
    return path
