"""Unit tests for logging configuration."""

import logging
import structlog

from cryptodb.logging_config import setup_logging


class TestSetupLogging:
    def test_dev_mode(self) -> None:
        # structlog can be reconfigured; just verify no exception
        setup_logging(level=logging.DEBUG)
        logger = structlog.get_logger()
        assert logger is not None
        # Calling again should also work
        setup_logging(level=logging.INFO)

    def test_prod_mode(self) -> None:
        setup_logging(level=logging.ERROR)
        logger = structlog.get_logger()
        assert logger is not None
