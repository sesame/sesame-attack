# -*- coding: utf-8 -*-
from .data_component_parser import DataComponentParser


class DataComponentsParser:
    def __init__(self):
        self._data_component_parser = DataComponentParser()

    def parse(self, data_components):
        return [
            self._data_component_parser.parse(data_component)
            for data_component in data_components
        ]
