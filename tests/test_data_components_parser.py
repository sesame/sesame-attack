# -*- coding: utf-8 -*-
import pytest
from sesame_attack.parser.data_components_parser import DataComponentsParser


class TestDataComponentsParser:
    @pytest.fixture
    def data_components(self, mitre_attack_data_container):
        domain = "enterprise-attack"
        mitre_attack_data = mitre_attack_data_container.get(domain)
        data_components = mitre_attack_data.get_datacomponents(
            remove_revoked_deprecated=True
        )
        return data_components

    def test_parse(self, data_components):
        data_components_parser = DataComponentsParser()
        data_components = data_components_parser.parse(data_components)

        assert len(data_components) > 0
