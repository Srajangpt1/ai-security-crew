"""Security analyzer for tickets.

This module analyzes ticket content to identify security-relevant information
and determine appropriate security requirements.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SecurityContext:
    """Security context extracted from a ticket."""

    technologies: list[str]
    security_keywords: set[str]
    risk_level: str  # "low", "medium", "high", "critical"
    security_categories: set[str]
    sensitive_data_types: set[str]
    attack_vectors: set[str]


class SecurityAnalyzer:
    """Analyzes ticket content for security implications."""

    def __init__(self) -> None:
        self._technology_patterns = self._load_technology_patterns()
        self._security_keywords = self._load_security_keywords()
        self._sensitive_data_patterns = self._load_sensitive_data_patterns()
        self._attack_vector_patterns = self._load_attack_vector_patterns()

    def analyze_ticket(self, ticket_data: dict[str, Any]) -> SecurityContext:
        """Analyze a ticket for security implications.

        Args:
            ticket_data: ticket data including summary, description, comments, etc.

        Returns:
            SecurityContext with identified security implications
        """
        # Extract text content from ticket
        text_content = self._extract_text_content(ticket_data)

        # Analyze for technologies
        technologies = self._identify_technologies(text_content)

        # Analyze for security keywords
        security_keywords = self._identify_security_keywords(text_content)

        # Analyze for sensitive data types
        sensitive_data_types = self._identify_sensitive_data(text_content)

        # Analyze for potential attack vectors
        attack_vectors = self._identify_attack_vectors(text_content)

        # Determine security categories
        security_categories = self._determine_security_categories(
            security_keywords, sensitive_data_types, attack_vectors
        )

        # Determine risk level
        risk_level = self._determine_risk_level(
            security_keywords, sensitive_data_types, attack_vectors, security_categories
        )

        return SecurityContext(
            technologies=technologies,
            security_keywords=security_keywords,
            risk_level=risk_level,
            security_categories=security_categories,
            sensitive_data_types=sensitive_data_types,
            attack_vectors=attack_vectors,
        )

    def _extract_text_content(self, ticket_data: dict[str, Any]) -> str:
        """Extract all text content from a ticket."""
        text_parts = []

        # Extract summary
        if "summary" in ticket_data:
            text_parts.append(str(ticket_data["summary"]))

        # Extract description
        if "description" in ticket_data:
            text_parts.append(str(ticket_data["description"]))

        # Extract comments
        if "comments" in ticket_data:
            for comment in ticket_data["comments"]:
                if isinstance(comment, dict) and "body" in comment:
                    text_parts.append(str(comment["body"]))

        # Extract custom fields that might contain text
        if "fields" in ticket_data:
            fields = ticket_data["fields"]
            for _field_name, field_value in fields.items():
                if isinstance(field_value, str) and len(field_value.strip()) > 0:
                    text_parts.append(field_value)

        return " ".join(text_parts).lower()

    def _identify_technologies(self, text_content: str) -> list[str]:
        """Identify technologies mentioned in the ticket content."""
        identified_technologies = []

        for tech_name, patterns in self._technology_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    if tech_name not in identified_technologies:
                        identified_technologies.append(tech_name)
                    break

        return identified_technologies

    def _identify_security_keywords(self, text_content: str) -> set[str]:
        """Identify security-related keywords in the ticket content."""
        found_keywords = set()

        for _category, keywords in self._security_keywords.items():
            for keyword in keywords:
                if re.search(rf"\b{re.escape(keyword)}\b", text_content, re.IGNORECASE):
                    found_keywords.add(keyword)

        return found_keywords

    def _identify_sensitive_data(self, text_content: str) -> set[str]:
        """Identify types of sensitive data mentioned in the ticket."""
        found_data_types = set()

        for data_type, patterns in self._sensitive_data_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    found_data_types.add(data_type)
                    break

        return found_data_types

    def _identify_attack_vectors(self, text_content: str) -> set[str]:
        """Identify potential attack vectors mentioned in the ticket."""
        found_vectors = set()

        for vector, patterns in self._attack_vector_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    found_vectors.add(vector)
                    break

        return found_vectors

    def _determine_security_categories(
        self,
        security_keywords: set[str],
        sensitive_data_types: set[str],
        attack_vectors: set[str],
    ) -> set[str]:
        """Determine relevant security categories based on analysis."""
        categories = set()

        # Map keywords to categories
        keyword_to_category = {
            # Authentication
            "login": "authentication",
            "password": "authentication",
            "auth": "authentication",
            "token": "authentication",
            "session": "authentication",
            "mfa": "authentication",
            "2fa": "authentication",
            "oauth": "authentication",
            "jwt": "authentication",
            "sso": "authentication",
            # Authorization
            "permission": "authorization",
            "role": "authorization",
            "access": "authorization",
            "admin": "authorization",
            "privilege": "authorization",
            "rbac": "authorization",
            "acl": "authorization",
            # Data validation
            "input": "data_validation",
            "validation": "data_validation",
            "sanitize": "data_validation",
            "validate": "data_validation",
            "form": "data_validation",
            # Cryptography
            "encrypt": "cryptography",
            "hash": "cryptography",
            "crypto": "cryptography",
            "ssl": "cryptography",
            "tls": "cryptography",
            "certificate": "cryptography",
            "signature": "cryptography",
            # API security
            "api": "api_security",
            "endpoint": "api_security",
            "rest": "api_security",
            "graphql": "api_security",
            "webhook": "api_security",
            # Database
            "database": "database",
            "sql": "database",
            "query": "database",
            "db": "database",
            "mongo": "database",
            "redis": "database",
            # Web security
            "web": "web_security",
            "http": "web_security",
            "https": "web_security",
            "cors": "web_security",
            "csrf": "web_security",
            "xss": "web_security",
            # Secrets management
            "secret": "secrets_management",
            "key": "secrets_management",
            "credential": "secrets_management",
            # Logging
            "log": "logging",
            "audit": "logging",
            "monitor": "logging",
            "trace": "logging",
            # Error handling
            "error": "error_handling",
            "exception": "error_handling",
            "fail": "error_handling",
        }

        for keyword in security_keywords:
            if keyword.lower() in keyword_to_category:
                categories.add(keyword_to_category[keyword.lower()])

        # Map sensitive data types to categories
        if sensitive_data_types:
            categories.add("data_validation")
            categories.add("secrets_management")

        # Map attack vectors to categories
        vector_to_category = {
            "sql_injection": "database",
            "xss": "web_security",
            "csrf": "web_security",
            "injection": "data_validation",
            "authentication_bypass": "authentication",
            "privilege_escalation": "authorization",
        }

        for vector in attack_vectors:
            if vector in vector_to_category:
                categories.add(vector_to_category[vector])

        return categories

    def _determine_risk_level(
        self,
        security_keywords: set[str],
        sensitive_data_types: set[str],
        attack_vectors: set[str],
        security_categories: set[str],
    ) -> str:
        """Determine the overall security risk level."""
        risk_score = 0

        # High-risk keywords
        high_risk_keywords = {
            "password",
            "token",
            "secret",
            "key",
            "credential",
            "admin",
            "privilege",
            "encrypt",
            "hash",
            "auth",
            "login",
            "session",
            "permission",
            "access",
        }

        # Critical keywords
        critical_keywords = {
            "authentication",
            "authorization",
            "injection",
            "xss",
            "csrf",
            "sql",
            "api",
            "database",
            "crypto",
            "ssl",
            "tls",
        }

        # Calculate risk score
        for keyword in security_keywords:
            if keyword.lower() in critical_keywords:
                risk_score += 3
            elif keyword.lower() in high_risk_keywords:
                risk_score += 2
            else:
                risk_score += 1

        # Add points for sensitive data
        risk_score += len(sensitive_data_types) * 2

        # Add points for attack vectors
        risk_score += len(attack_vectors) * 3

        # Add points for security categories
        risk_score += len(security_categories) * 1

        # Determine risk level
        if risk_score >= 15:
            return "critical"
        elif risk_score >= 10:
            return "high"
        elif risk_score >= 5:
            return "medium"
        else:
            return "low"

    def _load_technology_patterns(self) -> dict[str, list[str]]:
        """Load technology identification patterns."""
        return {
            "python": [
                r"\bpython\b",
                r"\bdjango\b",
                r"\bflask\b",
                r"\bfastapi\b",
                r"\bpip\b",
                r"\brequirements\.txt\b",
                r"\bvenv\b",
                r"\bvirtualenv\b",
            ],
            "javascript": [
                r"\bjavascript\b",
                r"\bnode\.?js\b",
                r"\bnodejs\b",
                r"\bnpm\b",
                r"\byarn\b",
                r"\breact\b",
                r"\bvue\b",
                r"\bangular\b",
                r"\btypescript\b",
                r"\bexpress\b",
            ],
            "java": [
                r"\bjava\b",
                r"\bspring\b",
                r"\bmaven\b",
                r"\bgradle\b",
                r"\bmvn\b",
                r"\bjar\b",
                r"\bwar\b",
                r"\bejb\b",
            ],
            "csharp": [
                r"\bc#\b",
                r"\bcsharp\b",
                r"\.net\b",
                r"\basp\.net\b",
                r"\bnuget\b",
                r"\bvisual studio\b",
                r"\bmsbuild\b",
            ],
            "go": [
                r"\bgo\b",
                r"\bgolang\b",
                r"\bgo mod\b",
                r"\bgoroutine\b",
                r"\bgin\b",
            ],
            "rust": [
                r"\brust\b",
                r"\bcargo\b",
                r"\bcrate\b",
                r"\btokio\b",
                r"\bactix\b",
            ],
            "php": [
                r"\bphp\b",
                r"\blaravel\b",
                r"\bsymfony\b",
                r"\bcomposer\b",
                r"\bwordpress\b",
            ],
            "database": [
                r"\bmysql\b",
                r"\bpostgresql\b",
                r"\bpostgres\b",
                r"\bmongodb\b",
                r"\bmongo\b",
                r"\bredis\b",
                r"\bsqlite\b",
                r"\boracle\b",
                r"\bsql server\b",
            ],
            "cloud": [
                r"\baws\b",
                r"\bamazon web services\b",
                r"\bazure\b",
                r"\bgoogle cloud\b",
                r"\bgcp\b",
                r"\bkubernetes\b",
                r"\bk8s\b",
                r"\bdocker\b",
                r"\bterraform\b",
            ],
        }

    def _load_security_keywords(self) -> dict[str, list[str]]:
        """Load security-related keywords by category."""
        return {
            "authentication": [
                "login",
                "logout",
                "password",
                "username",
                "auth",
                "authentication",
                "token",
                "jwt",
                "session",
                "cookie",
                "oauth",
                "sso",
                "mfa",
                "2fa",
                "two-factor",
                "biometric",
                "ldap",
                "active directory",
                "kerberos",
            ],
            "authorization": [
                "permission",
                "role",
                "access",
                "admin",
                "privilege",
                "rbac",
                "acl",
                "authorization",
                "grant",
                "deny",
                "allow",
                "forbidden",
                "unauthorized",
            ],
            "data_validation": [
                "input",
                "validation",
                "sanitize",
                "validate",
                "form",
                "parameter",
                "query string",
                "post data",
                "get data",
                "xss",
                "injection",
            ],
            "cryptography": [
                "encrypt",
                "decrypt",
                "hash",
                "crypto",
                "cryptography",
                "ssl",
                "tls",
                "certificate",
                "signature",
                "sign",
                "verify",
                "aes",
                "rsa",
                "sha",
                "md5",
                "bcrypt",
                "scrypt",
                "argon2",
            ],
            "api_security": [
                "api",
                "endpoint",
                "rest",
                "graphql",
                "webhook",
                "rate limit",
                "throttle",
                "cors",
                "headers",
                "request",
                "response",
            ],
            "database": [
                "database",
                "sql",
                "query",
                "db",
                "mongo",
                "redis",
                "injection",
                "orm",
                "migration",
                "backup",
                "restore",
            ],
            "web_security": [
                "web",
                "http",
                "https",
                "cors",
                "csrf",
                "xss",
                "clickjacking",
                "iframe",
                "csp",
                "content security policy",
                "hsts",
                "secure headers",
            ],
            "secrets_management": [
                "secret",
                "key",
                "credential",
                "password",
                "token",
                "api key",
                "private key",
                "public key",
                "certificate",
                "env",
                "environment",
            ],
            "logging": [
                "log",
                "logging",
                "audit",
                "monitor",
                "trace",
                "debug",
                "info",
                "warn",
                "error",
                "fatal",
                "siem",
                "security event",
            ],
            "error_handling": [
                "error",
                "exception",
                "fail",
                "failure",
                "handling",
                "try",
                "catch",
                "throw",
                "raise",
                "stack trace",
                "debug",
            ],
        }

    def _load_sensitive_data_patterns(self) -> dict[str, list[str]]:
        """Load patterns for identifying sensitive data types."""
        return {
            "personal_data": [
                r"\b(?:ssn|social security)\b",
                r"\b(?:credit card|cc)\b",
                r"\b(?:phone|telephone)\b",
                r"\b(?:address|street)\b",
                r"\b(?:email|e-mail)\b",
                r"\b(?:name|first name|last name)\b",
            ],
            "financial_data": [
                r"\b(?:bank|account|routing)\b",
                r"\b(?:payment|billing)\b",
                r"\b(?:transaction|transfer)\b",
                r"\b(?:invoice|receipt)\b",
            ],
            "health_data": [
                r"\b(?:medical|health|patient)\b",
                r"\b(?:diagnosis|treatment)\b",
                r"\b(?:prescription|medication)\b",
                r"\b(?:hipaa|phi)\b",
            ],
            "credentials": [
                r"\b(?:password|passwd|pwd)\b",
                r"\b(?:token|key|secret)\b",
                r"\b(?:credential|auth)\b",
                r"\b(?:api key|apikey)\b",
            ],
        }

    def _load_attack_vector_patterns(self) -> dict[str, list[str]]:
        """Load patterns for identifying potential attack vectors."""
        return {
            "sql_injection": [
                r"\b(?:sql injection|sqli)\b",
                r"\b(?:union select|drop table)\b",
                r"\b(?:or 1=1|and 1=1)\b",
                r"\b(?:'; --|'; drop)\b",
            ],
            "xss": [
                r"\b(?:xss|cross.site.scripting)\b",
                r"\b(?:<script|javascript:)\b",
                r"\b(?:onclick|onload|onerror)\b",
                r"\b(?:alert\(|document\.cookie)\b",
            ],
            "csrf": [
                r"\b(?:csrf|cross.site.request.forgery)\b",
                r"\b(?:same.origin)\b",
                r"\b(?:referer|origin)\b",
            ],
            "injection": [
                r"\b(?:injection|inject)\b",
                r"\b(?:command injection)\b",
                r"\b(?:ldap injection)\b",
                r"\b(?:nosql injection)\b",
            ],
            "authentication_bypass": [
                r"\b(?:auth bypass|authentication bypass)\b",
                r"\b(?:login bypass)\b",
                r"\b(?:session hijack)\b",
                r"\b(?:token manipulation)\b",
            ],
            "privilege_escalation": [
                r"\b(?:privilege escalation|priv esc)\b",
                r"\b(?:elevation of privilege)\b",
                r"\b(?:admin access|root access)\b",
                r"\b(?:sudo|su)\b",
            ],
        }
