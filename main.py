#!/usr/bin/env python3
"""SENTINEL main loop runner.

Starts background loops that don't have their own dedicated systemd service:
  - Daily digest at 07:00 MDT (analysis/digest.py)

Managed by sentinel-digest.service.
"""

import asyncio
import logging
import sys

sys.path.insert(0, "/opt/sentinel")

import config
from database import init_db
from analysis.digest import digest_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)-25s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("sentinel.main")


async def _main():
    config.get()
    init_db()
    logger.info("SENTINEL main runner started")
    await digest_loop()


if __name__ == "__main__":
    asyncio.run(_main())
