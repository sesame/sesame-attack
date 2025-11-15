# -*- coding: utf-8 -*-
from pathlib import Path
from mitreattack.stix20.MitreAttackData import MitreAttackData


class MitreAttackDataContainer:
    def __init__(self, enterprise_attack_path, mobile_attack_path, cache_dir=None):
        self._enterprise_attack = Path(enterprise_attack_path).expanduser().resolve()
        self._mobile_attack = Path(mobile_attack_path).expanduser().resolve()
        self._enterprise = None
        self._mobile = None

    def enterprise(self):
        return self.get("enterprise-attack")

    def mobile(self):
        return self.get("mobile-attack")

    def get(self, domain):
        match domain:
            case "enterprise-attack":
                self._enterprise = self._enterprise or MitreAttackData(
                    str(self._enterprise_attack)
                )
                return self._enterprise
            case "mobile-attack":
                self._mobile = self._mobile or MitreAttackData(str(self._mobile_attack))
                return self._mobile
            case _:
                raise ValueError(
                    f"domain must be enterprise-attack or mobile-attack. {domain}"
                )
