"""SENTINEL configuration loader.

Reads config.yaml, validates required fields, and provides
a singleton config dict accessible throughout the application.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Any

import yaml

CONFIG_PATH = Path("/opt/sentinel/config.yaml")

_config: dict | None = None

logger = logging.getLogger("sentinel.config")


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _validate(cfg: dict) -> list[str]:
    """Return a list of validation error strings (empty = valid)."""
    errors = []

    required_sections = ["general", "database", "wifi", "bluetooth", "frigate"]
    for section in required_sections:
        if section not in cfg:
            errors.append(f"Missing required section: {section}")

    if "database" in cfg:
        if not cfg["database"].get("path"):
            errors.append("database.path must be set")

    if cfg.get("wifi", {}).get("enabled"):
        iface = cfg["wifi"].get("interface")
        if not iface:
            errors.append("wifi.interface required when wifi is enabled")

    if cfg.get("bluetooth", {}).get("enabled"):
        adapter = cfg["bluetooth"].get("adapter")
        if not adapter:
            errors.append("bluetooth.adapter required when bluetooth is enabled")

    if cfg.get("frigate", {}).get("enabled"):
        if not cfg["frigate"].get("host"):
            errors.append("frigate.host required when frigate is enabled")

    if cfg.get("telegram", {}).get("enabled"):
        token = cfg["telegram"].get("bot_token", "")
        chat_id = cfg["telegram"].get("chat_id", "")
        if not token or "YOUR_" in token:
            errors.append("telegram.bot_token must be set when telegram is enabled")
        if not chat_id or "YOUR_" in str(chat_id):
            errors.append("telegram.chat_id must be set when telegram is enabled")

    return errors


def _ensure_dirs(cfg: dict) -> None:
    """Create required directories if they don't exist."""
    dirs = [
        cfg["general"]["data_dir"],
        cfg["general"]["log_dir"],
        os.path.dirname(cfg["database"]["path"]),
    ]
    if cfg.get("frigate", {}).get("snapshot_dir"):
        dirs.append(cfg["frigate"]["snapshot_dir"])

    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)


def load(path: str | Path | None = None) -> dict:
    """Load and validate configuration from YAML file.

    Args:
        path: Optional override for config file path.

    Returns:
        Validated configuration dictionary.

    Raises:
        SystemExit: If config file is missing or validation fails.
    """
    global _config

    config_path = Path(path) if path else CONFIG_PATH

    if not config_path.exists():
        logger.error("Config file not found: %s", config_path)
        sys.exit(1)

    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f)

    if not isinstance(cfg, dict):
        logger.error("Config file is empty or malformed: %s", config_path)
        sys.exit(1)

    errors = _validate(cfg)
    if errors:
        for err in errors:
            logger.error("Config validation error: %s", err)
        sys.exit(1)

    _ensure_dirs(cfg)
    _config = cfg
    logger.info("Configuration loaded from %s", config_path)
    return cfg


def get() -> dict:
    """Return the loaded config, loading from default path if needed."""
    global _config
    if _config is None:
        return load()
    return _config


def get_section(section: str) -> dict:
    """Return a specific config section."""
    cfg = get()
    return cfg.get(section, {})


def reload() -> dict:
    """Force-reload configuration from disk."""
    global _config
    _config = None
    return load()


def setup_logging() -> None:
    """Configure logging based on config settings."""
    cfg = get()
    log_dir = Path(cfg["general"]["log_dir"])
    log_level = getattr(logging, cfg["general"].get("log_level", "INFO").upper(), logging.INFO)

    log_dir.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)-25s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler - main log
    file_handler = logging.FileHandler(log_dir / "sentinel.log")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    # Root sentinel logger
    root_logger = logging.getLogger("sentinel")
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
