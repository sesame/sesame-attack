# -*- coding: utf-8 -*-


class DataComponentParser:
    def parse(self, data_component):
        data_component_dict = dict(data_component)
        parsed = {}

        keys = ["created", "description", "name", "modified"]

        for key in keys:
            parsed[key] = data_component_dict[key]

        parsed["stix_id"] = data_component_dict["id"]
        external_references = data_component_dict["external_references"]
        url, external_id = self._parse_external_references(external_references)
        parsed["url"] = url
        parsed["attack_id"] = external_id
        parsed["domains"] = data_component_dict["x_mitre_domains"]
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
