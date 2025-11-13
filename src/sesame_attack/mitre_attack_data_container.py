# -*- coding: utf-8 -*-
from pathlib import Path
from mitreattack.stix20.MitreAttackData import MitreAttackData

class MitreAttackDataContainer:
    def __init(self, enterprise_attack_path, mobile_attack_path):
        self._enterprise_attack = Path(enterprise_attack_path).expanduser().resolve()
        self._mobile_attack = Path(mobile_attack_path).expanduser().resolve()
        self._enterprise = None
        self._mobile = None

    def enterprise(self):
        return self._enterprise or MitreAttackData(str(self._enterprise_attack))

    def mobile(self):
        return self._mobile or MitreAttackData(str(self._mobile_attack))
