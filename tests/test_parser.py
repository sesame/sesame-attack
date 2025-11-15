# -*- coding: utf-8 -*-
import pytest
from sesame_attack.parser import DataComponentsParser
from sesame_attack.parser import AnalyticsParser
from sesame_attack.parser import DetectionStrategiesParser
from sesame_attack.parser import TechniquesParser


class TestDataComponentsParser:
    @pytest.fixture
    def sut(self):
        return DataComponentsParser()

    @pytest.fixture
    def data_components(self, mitre_attack_data_container):
        domain = "enterprise-attack"
        mitre_attack_data = mitre_attack_data_container.get(domain)
        return mitre_attack_data.get_datacomponents(remove_revoked_deprecated=True)

    def test_parse(self, sut, data_components):
        data_components = sut.parse(data_components)
        actual = data_components[0]

        assert {
            "attack_id": "DC0084",
            "created": "2021-10-20T15:05:19.274Z",
            "description": "Requests for authentication credentials via Kerberos or other "
            "methods like NTLM and LDAP queries. Examples:\n"
            "\n"
            "- Kerberos TGT and Service Tickets (Event IDs 4768, 4769)\n"
            "- NTLM Authentication Events\n"
            "- LDAP Bind Requests\n"
            "\n"
            "*Data Collection Measures:*\n"
            "\n"
            "- Security Event Logging:\n"
            '    - Enable "`Audit Kerberos Authentication Service`" or '
            '"`Audit Kerberos Service Ticket Operations`."\n'
            "    - Captured Events: IDs 4768, 4769, 4624.\n"
            "- Windows Event Forwarding (WEF): Forward domain controller "
            "logs to SIEM.\n"
            "- SIEM Integration: Use tools like Splunk or Azure Sentinel "
            "for log analysis.\n"
            "- Kerberos Debug Logging:\n"
            "    - Registry Key: "
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters.\n"
            "    - Set DWORD LogLevel to 1.\n"
            "- Azure AD Logs: Monitor Sign-In Logs for authentication and "
            "policy issues.\n"
            "- Enable EDR Monitoring:\n"
            "    - Use EDR to detect suspicious processes querying "
            "authentication mechanisms (e.g., lsass.exe memory access).",
            "domains": ["enterprise-attack"],
            "modified": "2025-10-22T18:41:09.269Z",
            "name": "Active Directory Credential Request",
            "stix_id": "x-mitre-data-component--02d090b6-8157-48da-98a2-517f7edd49fc",
            "url": "https://attack.mitre.org/data-components/DC0084",
        } == actual


class TestAnalyticsParser:
    @pytest.fixture
    def sut(self):
        return AnalyticsParser()

    @pytest.fixture
    def analytics(self, mitre_attack_data_container):
        domain = "enterprise-attack"
        mitre_attack_data = mitre_attack_data_container.get(domain)
        return mitre_attack_data.get_analytics(remove_revoked_deprecated=True)

    def test_parse(self, sut, analytics):
        analytics = sut.parse(analytics)
        actual = analytics[0]

        assert {
            "attack_id": "AN0110",
            "created": "2025-10-21T15:10:28.402Z",
            "description": "Monitor /var/log/audit/audit.log and DNS resolver logs for "
            "repeated failed lookups or connections to high-entropy domain "
            "names. Correlate suspicious DNS queries with process lineage "
            "(e.g., Python, bash, or unusual system daemons).",
            "domains": ["enterprise-attack"],
            "log_source_references": [
                {
                    "channel": "socket/connect",
                    "name": "auditd:SYSCALL",
                    "x_mitre_data_component_ref": "x-mitre-data-component--a7f22107-02e5-4982-9067-6625d4a1765a",
                },
                {
                    "channel": "Query to suspicious domain with high "
                    "entropy or low reputation",
                    "name": "linux:syslog",
                    "x_mitre_data_component_ref": "x-mitre-data-component--3772e279-27d6-477a-9fe3-c6beb363594c",
                },
            ],
            "modified": "2025-10-21T15:10:28.402Z",
            "name": "Analytic 0110",
            "stix_id": "x-mitre-analytic--00112bcc-174f-4201-ac81-fe3edd1292e6",
            "url": "https://attack.mitre.org/detectionstrategies/DET0039#AN0110",
        } == actual


class TestDetectionStrategiesParser:
    @pytest.fixture
    def sut(self):
        return DetectionStrategiesParser()

    @pytest.fixture
    def detection_strategies(self, mitre_attack_data_container):
        domain = "enterprise-attack"
        mitre_attack_data = mitre_attack_data_container.get(domain)
        return mitre_attack_data.get_detectionstrategies(remove_revoked_deprecated=True)

    def test_parse(self, sut, detection_strategies):
        detection_strategies = sut.parse(detection_strategies)
        actual = detection_strategies[0]

        assert {
            "analytic_refs": [
                "x-mitre-analytic--98f8728d-ff74-47cb-b884-25071a21f77e",
                "x-mitre-analytic--e716b209-5b06-4bc4-843f-cbe4c51ddc0d",
                "x-mitre-analytic--69562961-14e6-42a7-9f8a-24ac00f6404e",
                "x-mitre-analytic--b053dbd4-ad1e-45e1-a6b7-af2a5d931c82",
            ],
            "attack_id": "DET0237",
            "created": "2025-10-21T15:10:28.402Z",
            "description": None,
            "domains": ["enterprise-attack"],
            "modified": "2025-10-21T15:10:28.402Z",
            "name": "Detection Strategy for Boot or Logon Initialization Scripts: RC "
            "Scripts",
            "stix_id": "x-mitre-detection-strategy--be6a466c-40c6-4611-9b68-7cfcbcb35fb0",
            "url": "https://attack.mitre.org/detectionstrategies/DET0237",
        } == actual


class TestTechniquesParser:
    @pytest.fixture
    def sut(self):
        return TechniquesParser()

    @pytest.fixture
    def techniques(self, mitre_attack_data_container):
        domain = "enterprise-attack"
        mitre_attack_data = mitre_attack_data_container.get(domain)
        return mitre_attack_data.get_techniques(remove_revoked_deprecated=True)

    def test_parse(self, sut, techniques):
        techniques = sut.parse(techniques)
        actual = techniques[0]

        assert {
            "attack_id": "T1055.011",
            "created": "2020-01-14T17:18:32.126Z",
            "description": "Adversaries may inject malicious code into process via Extra "
            "Window Memory (EWM) in order to evade process-based defenses "
            "as well as possibly elevate privileges. EWM injection is a "
            "method of executing arbitrary code in the address space of a "
            "separate live process. \n"
            "\n"
            "Before creating a window, graphical Windows-based processes "
            "must prescribe to or register a windows class, which "
            "stipulate appearance and behavior (via windows procedures, "
            "which are functions that handle input/output of "
            "data).(Citation: Microsoft Window Classes) Registration of "
            "new windows classes can include a request for up to 40 bytes "
            "of EWM to be appended to the allocated memory of each "
            "instance of that class. This EWM is intended to store data "
            "specific to that window and has specific application "
            "programming interface (API) functions to set and get its "
            "value. (Citation: Microsoft GetWindowLong function) "
            "(Citation: Microsoft SetWindowLong function)\n"
            "\n"
            "Although small, the EWM is large enough to store a 32-bit "
            "pointer and is often used to point to a windows procedure. "
            "Malware may possibly utilize this memory location in part of "
            "an attack chain that includes writing code to shared sections "
            "of the process’s memory, placing a pointer to the code in "
            "EWM, then invoking execution by returning execution control "
            "to the address in the process’s EWM.\n"
            "\n"
            "Execution granted through EWM injection may allow access to "
            "both the target process's memory and possibly elevated "
            "privileges. Writing payloads to shared sections also avoids "
            "the use of highly monitored API calls such as "
            "<code>WriteProcessMemory</code> and "
            "<code>CreateRemoteThread</code>.(Citation: Elastic Process "
            "Injection July 2017) More sophisticated malware samples may "
            "also potentially bypass protection mechanisms such as data "
            "execution prevention (DEP) by triggering a combination of "
            "windows procedures and other system functions that will "
            "rewrite the malicious payload inside an executable portion of "
            "the target process.  (Citation: MalwareTech Power Loader Aug "
            "2013) (Citation: WeLiveSecurity Gapz and Redyms Mar 2013)\n"
            "\n"
            "Running code in the context of another process may allow "
            "access to the process's memory, system/network resources, and "
            "possibly elevated privileges. Execution via EWM injection may "
            "also evade detection from security products since the "
            "execution is masked under a legitimate process. ",
            "domains": ["enterprise-attack"],
            "modified": "2025-10-24T17:48:19.059Z",
            "name": "Extra Window Memory Injection",
            "stix_id": "attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298",
            "url": "https://attack.mitre.org/techniques/T1055/011",
        } == actual
