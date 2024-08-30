"""Unittests for KB generator."""

import os.path
from pytest_mock import plugin
from pyfakefs import fake_filesystem

from tests import utils
from tools import kb_generator


def testGenerateKB_whenVulnerabilityProvided_returnsKBEntry(
    mocker: plugin.MockerFixture,
) -> None:
    """generate_kb is responsible for generating KB entries from a vulnerability name.
    when provided with a valid vulnerability name, this function should return a dict
    representing a KB entry
    """
    mocker.patch(
        "openai.api_resources.chat_completion.ChatCompletion.create",
        side_effect=utils.mock_chat_completion_create,
    )
    vulnerability = kb_generator.Vulnerability(
        "Sql Injection", kb_generator.RiskRating.HIGH, kb_generator.Platform.WEB
    )

    kbentry = kb_generator.generate_kb(vulnerability)

    assert (
        "SQL injection is a type of security vulnerability that allows an attacker to inject malicious SQL "
        "statements into an application's database" in kbentry.description
    )
    assert "import 'package:sqflite/sqflite.dart';" in kbentry.description
    assert (
        "it is important to use parameterized queries or prepared statements instead of concatenating user input "
        "directly into SQL statements. " in kbentry.recommendation
    )
    assert kbentry.meta["risk_rating"] == "high"
    assert (
        kbentry.meta["short_description"]
        == "SQL Injection vulnerability allows an attacker to execute malicious SQL "
        "queries to the database,potentially gaining access to sensitive data or "
        "performing unauthorized actions."
    )
    assert kbentry.meta["references"] == {
        "NIST": "https://nvd.nist.gov/vuln/detail/CVE-2019-16759",
        "OWASP ": "https: //owasp.org/www-community/attacks/SQL_Injection",
        "SANS": "https://www.sans.org/top-25-software-errors/#cat3",
    }
    assert kbentry.meta["title"] == "SQL Injection Vulnerability"
    assert kbentry.meta["security_issue"] is True
    assert kbentry.meta["privacy_issue"] is False
    assert kbentry.meta["categories"] == {
        "OWASP_MASVS_L1": [
            "V2: Authentication and Session Management",
            "V3: Cryptography",
            "V4: Network Communication",
            "V5: Platform Interaction",
            "V6: Code Quality and Build Settings",
        ],
        "OWASP_MASVS_L2": ["V7: Data Protection", "V8: Resilience Against Attack"],
    }


def testDumpKB_whenPathIsValid_writesFiles(
    mocker: plugin.MockerFixture, fs: fake_filesystem.FakeFilesystem
) -> None:
    """Test creation of KB files."""
    vulnerability = kb_generator.Vulnerability(
        name="XSS",
        platform=kb_generator.Platform.WEB,
        risk_rating=kb_generator.RiskRating.HIGH,
    )
    kbentry = kb_generator.KBEntry(
        vulnerability=vulnerability,
        description="Description",
        recommendation="Recommendation",
        meta={"Meta": "Meta data"},
    )
    kb_generator.dump_kb(kbentry)

    assert os.path.exists("WEB_SERVICE/WEB/_HIGH") is True
    assert os.path.exists("WEB_SERVICE/WEB/_HIGH/description.md") is True
    assert os.path.exists("WEB_SERVICE/WEB/_HIGH/recommendation.md") is True
    assert os.path.exists("WEB_SERVICE/WEB/_HIGH/meta.json") is True
