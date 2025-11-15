# -*- coding: utf-8 -*-
from abc import ABCMeta
from abc import abstractmethod


class BaseObject(metaclass=ABCMeta):
    def __init__(self, keys):
        self._keys = keys

    @abstractmethod
    def parse(self, obj):
        dict_ = dict(obj)
        parsed = {}

        for key in self._keys:
            parsed[key] = dict_[key]

        parsed["stix_id"] = dict_["id"]
        external_references = dict_["external_references"]
        url, external_id = self._parse_external_references(external_references)
        parsed["url"] = url
        parsed["attack_id"] = external_id
        parsed["domains"] = dict_["x_mitre_domains"]
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
    KEYS = ["created", "description", "name", "modified"]

    def __init__(self):
        keys = self.KEYS
        super().__init__(keys)

    def parse(self, obj):
        parsed = super().parse(obj)
        return parsed


class DataComponentsParser(BaseObjects):
    def __init__(self):
        super().__init__(DataComponentParser())


class AnalyticParser(BaseObject):
    KEYS = ["created", "description", "name", "modified"]

    def __init__(self):
        keys = self.KEYS
        super().__init__(keys)

    def parse(self, obj):
        parsed = super().parse(obj)
        parsed["log_source_references"] = dict(obj)["x_mitre_log_source_references"]
        return parsed


class AnalyticsParser(BaseObjects):
    def __init__(self):
        super().__init__(AnalyticParser())


class DetectionStrategyParser(BaseObject):
    KEYS = ["created", "description", "name", "modified"]

    def __init__(self):
        keys = self.KEYS
        super().__init__(keys)

    def parse(self, obj):
        parsed = super().parse(obj)
        parsed["analytic_refs"] = dict(obj)["x_mitre_analytic_refs"]
        return parsed


class DetectionStrategiesParser(BaseObjects):
    def __init__(self):
        super().__init__(DetectionStrategyParser())
