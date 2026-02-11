"""Configuration loader for EAST tool."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class ClientInfo:
    name: str = "Unknown Client"
    contact: str = ""


@dataclass
class TestConfig:
    enabled: list[str] = field(default_factory=lambda: [
        "ssl_labs", "mozilla_observatory",
    ])
    disabled: list[str] = field(default_factory=list)


@dataclass
class OutputConfig:
    format: str = "docx"
    filename_template: str = "EAST_{client}_{date}.docx"
    include_raw_data: bool = True
    screenshots: bool = True


@dataclass
class BrandingConfig:
    logo: str = "assets/logo.png"
    company_name: str = "Your Security Company"
    color_scheme: str = "professional"


@dataclass
class APIKeys:
    google_pagespeed: str = ""
    mxtoolbox: str = ""


@dataclass
class SSLFallbackConfig:
    """Controls local-TLS fallback when SSL Labs is unavailable."""
    enabled: bool = False
    tool_preference: list[str] = field(default_factory=lambda: [
        "sslyze", "testssl", "openssl",
    ])
    timeout: int = 120
    retries: int = 5


@dataclass
class EASTConfig:
    domains: list[str] = field(default_factory=list)
    client_info: ClientInfo = field(default_factory=ClientInfo)
    tests: TestConfig = field(default_factory=TestConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    branding: BrandingConfig = field(default_factory=BrandingConfig)
    api_keys: APIKeys = field(default_factory=APIKeys)
    ssllabs_email: str = ""
    ssllabs_usecache: bool = True
    ssl_fallback: SSLFallbackConfig = field(default_factory=SSLFallbackConfig)

    @classmethod
    def from_yaml(cls, path: str) -> "EASTConfig":
        """Load configuration from a YAML file."""
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        config = cls()

        if "domains" in data:
            config.domains = data["domains"]

        if "client_info" in data:
            ci = data["client_info"]
            config.client_info = ClientInfo(
                name=ci.get("name", "Unknown Client"),
                contact=ci.get("contact", ""),
            )

        if "tests" in data:
            t = data["tests"]
            config.tests = TestConfig(
                enabled=t.get("enabled", []),
                disabled=t.get("disabled", []),
            )

        if "output" in data:
            o = data["output"]
            config.output = OutputConfig(
                format=o.get("format", "docx"),
                filename_template=o.get("filename_template", "EAST_{client}_{date}.docx"),
                include_raw_data=o.get("include_raw_data", True),
                screenshots=o.get("screenshots", True),
            )

        if "branding" in data:
            b = data["branding"]
            config.branding = BrandingConfig(
                logo=b.get("logo", "assets/logo.png"),
                company_name=b.get("company_name", "Your Security Company"),
                color_scheme=b.get("color_scheme", "professional"),
            )

        if "api_keys" in data:
            ak = data["api_keys"]
            config.api_keys = APIKeys(
                google_pagespeed=ak.get("google_pagespeed", ""),
                mxtoolbox=ak.get("mxtoolbox", ""),
            )

        if "ssllabs_email" in data:
            config.ssllabs_email = data["ssllabs_email"]

        if "ssllabs_usecache" in data:
            config.ssllabs_usecache = bool(data["ssllabs_usecache"])

        if "ssl_fallback" in data:
            fb = data["ssl_fallback"]
            config.ssl_fallback = SSLFallbackConfig(
                enabled=fb.get("enabled", False),
                tool_preference=fb.get("tool_preference", [
                    "sslyze", "testssl", "openssl",
                ]),
                timeout=fb.get("timeout", 120),
                retries=fb.get("retries", 5),
            )

        return config

    @classmethod
    def default(cls) -> "EASTConfig":
        """Create a default configuration."""
        return cls()

    def is_test_enabled(self, test_name: str) -> bool:
        """Check if a specific test is enabled."""
        if test_name in self.tests.disabled:
            return False
        if not self.tests.enabled:
            return True
        return test_name in self.tests.enabled
