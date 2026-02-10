"""Base test runner class for EAST tool."""

import io
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Container for test results."""
    test_name: str
    domain: str
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = False
    grade: str = ""
    score: Optional[int] = None
    max_score: int = 100
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    recommendations: list[dict[str, str]] = field(default_factory=list)
    visuals: dict[str, io.BytesIO] = field(default_factory=dict)
    tables: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    @property
    def score_percentage(self) -> float:
        if self.score is not None and self.max_score > 0:
            return self.score / self.max_score
        return 0.0


class TestRunner(ABC):
    """Base class for all EAST test runners."""

    name: str = "base"
    description: str = "Base test"

    def __init__(self, domain: str):
        self.domain = domain
        self.logger = logging.getLogger(f"east.tests.{self.name}")

    @abstractmethod
    def run(self) -> TestResult:
        """Execute the test and return results.

        Returns:
            TestResult containing all test data, visuals, and recommendations.
        """
        ...

    def _create_error_result(self, error_msg: str) -> TestResult:
        """Create a TestResult indicating an error."""
        return TestResult(
            test_name=self.name,
            domain=self.domain,
            success=False,
            summary=f"Test failed: {error_msg}",
            error=error_msg,
            recommendations=[{
                "severity": "info",
                "text": f"The {self.name} test could not be completed. "
                        f"Error: {error_msg}. Please try again later.",
            }],
        )
