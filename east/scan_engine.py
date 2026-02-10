"""Async scan orchestration shared by CLI and web UI."""

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable, Awaitable

from east.config import EASTConfig
from east.tests.base import TestResult

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str], None]


@dataclass
class ScanConcurrency:
    max_parallel_tests: int = 6
    ssl_labs_parallel: int = 1
    observatory_parallel: int = 2


class ScanEngine:
    """Run tests across domains asynchronously with rate-limited runners."""

    def __init__(self, test_registry: dict[str, type], concurrency: ScanConcurrency | None = None):
        self.test_registry = test_registry
        self.concurrency = concurrency or ScanConcurrency()

    async def run(
        self,
        config: EASTConfig,
        tests_to_run: list[str],
        on_log: ProgressCallback | None = None,
    ) -> dict[str, list[TestResult]]:
        results: dict[str, list[TestResult]] = {d: [] for d in config.domains}

        test_sem = asyncio.Semaphore(self.concurrency.max_parallel_tests)
        ssl_sem = asyncio.Semaphore(self.concurrency.ssl_labs_parallel)
        obs_sem = asyncio.Semaphore(self.concurrency.observatory_parallel)
        lock = asyncio.Lock()

        async def run_single(domain: str, test_name: str):
            runner_cls = self.test_registry[test_name]
            sem = ssl_sem if test_name == "ssl_labs" else obs_sem if test_name == "mozilla_observatory" else test_sem

            async with sem:
                if on_log:
                    on_log(f"[{domain}] Starting test: {test_name}")
                try:
                    if test_name == "ssl_labs":
                        runner = runner_cls(domain, email=config.ssllabs_email, use_cache=config.ssllabs_usecache)
                    elif test_name == "performance":
                        runner = runner_cls(domain, pagespeed_key=config.api_keys.google_pagespeed)
                    else:
                        runner = runner_cls(domain)

                    result = await asyncio.to_thread(runner.run)
                except Exception as exc:
                    result = TestResult(
                        test_name=test_name,
                        domain=domain,
                        success=False,
                        error=str(exc),
                        summary=f"{test_name} failed: {exc}",
                    )

                async with lock:
                    results[domain].append(result)

                status = "ok" if result.success else "error"
                if on_log:
                    on_log(f"[{domain}] Finished test: {test_name} ({status})")

        coros = [run_single(domain, test_name) for domain in config.domains for test_name in tests_to_run if test_name in self.test_registry]
        await asyncio.gather(*coros)
        return results
