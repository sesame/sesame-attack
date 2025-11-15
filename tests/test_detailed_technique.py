# -*- coding: utf-8 -*-
from sesame_attack.detailed_technique import DetailedTechniqueBuilder


class TestDetailedTechnique:
    def test_build(self, mitre_attack_data_container):
        builder = DetailedTechniqueBuilder(mitre_attack_data_container)
        mitre_attack_data = mitre_attack_data_container.get("enterprise-attack")
        technique = mitre_attack_data.get_object_by_attack_id("T1003", "attack-pattern")
        detailed_technique = builder.build("enterprise-attack", technique)

        assert "OS Credential Dumping" == detailed_technique._technique.name
        assert "T1003" == (
            detailed_technique._technique.external_references[0].external_id
        )
        assert len(detailed_technique._detection_strategies) > 0

        for detection_strategy in detailed_technique._detection_strategies:
            assert len(detection_strategy._analytics) > 0

            for analytic in detection_strategy._analytics:
                assert analytic._analytic.name is not None
                assert analytic._analytic.external_references[0].external_id is not None
                # Data components can be empty, so we don't assert their presence here.

    def test_to_dict(self, mitre_attack_data_container):
        builder = DetailedTechniqueBuilder(mitre_attack_data_container)
        mitre_attack_data = mitre_attack_data_container.get("enterprise-attack")
        technique = mitre_attack_data.get_object_by_attack_id("T1003", "attack-pattern")
        detailed_technique = builder.build("enterprise-attack", technique)
        detailed_technique_dict = detailed_technique.to_dict()

        assert detailed_technique_dict["name"] == "OS Credential Dumping"
        assert detailed_technique_dict["attack_id"] == "T1003"
        assert len(detailed_technique_dict["detection_strategies"]) > 0

        for detection_strategy_dict in detailed_technique_dict["detection_strategies"]:
            assert len(detection_strategy_dict["analytics"]) > 0

            for analytic_dict in detection_strategy_dict["analytics"]:
                assert analytic_dict["name"] is not None
                assert analytic_dict["attack_id"] is not None
                # Data components can be empty, so we don't assert their presence here.
