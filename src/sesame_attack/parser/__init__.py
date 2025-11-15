# -*- coding: utf-8 -*-
from abc import ABCMeta
from abc import abstractmethod
from stix2.utils import STIXdatetime
from typing import Any


class BaseObject(metaclass=ABCMeta):
    KEYS = ["created", "description", "name", "modified"]

    def __init__(self):
        self._keys = self.KEYS

    @abstractmethod
    def parse(self, obj):
        dict_: dict[Any, str | STIXdatetime] = dict(obj)
        parsed = {}

        for key in self._keys:
            match key:
                case "description" | "name":
                    parsed[key] = dict_.get(key)
                case "created" | "modified":
                    parsed[key] = (
                        dict_[key]
                        .isoformat(timespec="milliseconds")
                        .replace("+00:00", "Z")
                    )
                case _:
                    raise ValueError(f"unsupported key: {key}")

        if stix_id := dict_.get("id"):
            parsed["stix_id"] = stix_id

        if external_references := dict_.get("external_references"):
            url, external_id = self._parse_external_references(external_references)
            parsed["url"] = url
            parsed["attack_id"] = external_id

        if domains := dict_.get("x_mitre_domains"):
            parsed["domains"] = domains

        return parsed

    @staticmethod
    def _parse_external_references(external_references):
        url = None
        external_id = None

        for external_reference in external_references:
            if external_reference.source_name == "mitre-attack":
                url = external_reference.url
                external_id = external_reference.external_id
                break

        if url is None or external_id is None:
            raise ValueError(f"can't find url or external_id in external_reference.")

        return url, external_id


class BaseObjects(metaclass=ABCMeta):
    def __init__(self, parser):
        self._parser = parser

    def parse(self, objs):
        return [self._parser.parse(obj) for obj in objs]


class DataComponentParser(BaseObject):
    def parse(self, obj):
        parsed = super().parse(obj)
        return parsed


class DataComponentsParser(BaseObjects):
    def __init__(self):
        super().__init__(DataComponentParser())


class AnalyticParser(BaseObject):
    def parse(self, obj):
        parsed = super().parse(obj)
        parsed["log_source_references"] = dict(obj).get("x_mitre_log_source_references")
        return parsed


class AnalyticsParser(BaseObjects):
    def __init__(self):
        super().__init__(AnalyticParser())


class DetectionStrategyParser(BaseObject):
    def parse(self, obj):
        parsed = super().parse(obj)
        parsed["analytic_refs"] = dict(obj)["x_mitre_analytic_refs"]
        return parsed


class DetectionStrategiesParser(BaseObjects):
    def __init__(self):
        super().__init__(DetectionStrategyParser())


class TechniqueParser(BaseObject):
    def parse(self, obj):
        parsed = super().parse(obj)
        dict_ = dict(obj)
        parsed["platforms"] = sorted(dict_.get("x_mitre_platforms", []))
        parsed["is_subtechnique"] = dict_.get("x_mitre_is_subtechnique", False)

        if kill_chain_phases := dict_.get("kill_chain_phases"):
            parsed["tactics"] = sorted(
                [
                    phase.phase_name
                    for phase in kill_chain_phases
                    if phase.kill_chain_name == "mitre-attack"
                ]
            )

        return parsed


class TechniquesParser(BaseObjects):
    def __init__(self):
        super().__init__(TechniqueParser())
