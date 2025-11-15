# -*- coding: utf-8 -*-
from .parser import TechniqueParser


class DetailedTechniqueBuilder:
    def __init__(self, mitre_attack_data_container):
        self._mitre_attack_data_container = mitre_attack_data_container
        self._mitre_attack_data = None
        self._techniques_map = {}

    def build(self, domain, technique):
        self._mitre_attack_data = self._mitre_attack_data_container.get(domain)

        if domain not in self._techniques_map:
            self._techniques_map[domain] = (
                self._mitre_attack_data.get_all_detection_strategies_detecting_all_techniques()
            )

        techniques_map = self._techniques_map[domain]
        detailed_technique = DetailedTechnique(technique)
        detection_strategies = self._get_detection_strategies(technique, techniques_map)

        for detection_strategy in detection_strategies:
            detailed_detection_strategy = DetailedDetectionStrategy(detection_strategy)
            analytics = self._get_analytics(detection_strategy)

            for analytic in analytics:
                data_components = self._get_data_components(analytic)
                detailed_analytic = DetailedAnalytic(analytic, data_components)
                detailed_detection_strategy.append_detailed_analytic(detailed_analytic)

            detailed_technique.append_detection_detailed_detection_strategy(
                detailed_detection_strategy
            )

        return detailed_technique

    def _get_data_components(self, analytic):
        log_source_references = analytic.get("x_mitre_log_source_references")
        data_components = []

        if not log_source_references:
            return data_components

        for log_source_reference in log_source_references:
            data_component_stix_id = log_source_reference.get(
                "x_mitre_data_component_ref"
            )
            if data_component_stix_id:
                data_component = self._mitre_attack_data.get_object_by_stix_id(
                    data_component_stix_id
                )
                data_components.append(data_component)

        return data_components

    def _get_analytics(self, detection_strategy):
        analytics_ids = detection_strategy.get("x_mitre_analytic_refs")

        if not analytics_ids:
            return []

        return [
            self._mitre_attack_data.get_object_by_stix_id(analytic_id)
            for analytic_id in analytics_ids
        ]

    @staticmethod
    def _get_detection_strategies(technique, techniques_map):
        if detection_strategies := techniques_map.get(technique.id):
            return [
                detection_strategy["object"]
                for detection_strategy in detection_strategies
            ]
        return []


class DetailedTechnique:
    def __init__(self, technique):
        self._technique = technique
        self._detection_strategies = []

    def append_detection_detailed_detection_strategy(self, detailed_detection_strategy):
        self._detection_strategies.append(detailed_detection_strategy)

    def to_dict(self):
        parsed_technique = TechniqueParser().parse(self._technique)

        return {
            "technique": parsed_technique,
        }


class DetailedDetectionStrategy:
    def __init__(self, detection_strategy):
        self._detection_strategy = detection_strategy
        self._analytics = []

    def append_detailed_analytic(self, detailed_analytic):
        self._analytics.append(detailed_analytic)


class DetailedAnalytic:
    def __init__(self, analytic, data_components):
        self._analytic = analytic
        self._data_components = data_components
