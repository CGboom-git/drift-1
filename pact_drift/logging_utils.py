def debug(logger, enabled: bool, message: str) -> None:
    if enabled and logger is not None:
        logger.info("PACT-DRIFT: %s", message)
