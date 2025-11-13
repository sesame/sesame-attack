# -*- coding: utf-8 -*-
import pytest
from pathlib import Path
from sesame_attack.mitre_attack_data_container import MitreAttackDataContainer


@pytest.fixture
def rootdir(request):
    return Path(request.config.rootdir)


@pytest.fixture
def cti_dir(rootdir):
    return rootdir / "cti"


@pytest.fixture
def attack_data_paths(cti_dir):
    return {
        "enterprise-attack": str(
            cti_dir / "enterprise-attack" / "enterprise-attack.json"
        ),
        "mobile-attack": str(cti_dir / "mobile-attack" / "mobile-attack.json"),
    }


@pytest.fixture
def mitre_attack_data_container(attack_data_paths):
    return MitreAttackDataContainer(
        attack_data_paths["enterprise-attack"], attack_data_paths["mobile-attack"]
    )
