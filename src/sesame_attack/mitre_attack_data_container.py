# -*- coding: utf-8 -*-
from pathlib import Path
from mitreattack.stix20.MitreAttackData import MitreAttackData


class MitreAttackDataContainer:
    def __init__(self, enterprise_attack_path, mobile_attack_path):
        self._enterprise_attack = Path(enterprise_attack_path).expanduser().resolve()
        self._mobile_attack = Path(mobile_attack_path).expanduser().resolve()
        self._enterprise = None
        self._mobile = None

    def enterprise(self):
        return self.get("enterprise-attack")

    def mobile(self):
        return self.get("mobile-attack")

    def get(self, domain):
        mitre_attack_data = None

        match domain:
            case "enterprise-attack":
                mitre_attack_data = self._enterprise or MitreAttackData(
                    str(self._enterprise_attack)
                )
            case "mobile-attack":
                mitre_attack_data = self._mobile or MitreAttackData(
                    str(self._mobile_attack)
                )
            case _:
                raise ValueError(
                    f"domain must be enterprise-attack or mobile-attack. {domain}"
                )

        return mitre_attack_data
