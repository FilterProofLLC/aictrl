"""JSON output utilities for bbail."""

import json
import sys
from typing import Any


def output_json(data: Any, pretty: bool = False, file=None) -> None:
    """Output data as JSON to stdout or specified file.

    Args:
        data: Data to serialize as JSON.
        pretty: If True, output indented JSON for human readability.
        file: File object to write to (defaults to stdout).
    """
    if file is None:
        file = sys.stdout

    indent = 2 if pretty else None
    json.dump(data, file, indent=indent, default=str)
    file.write("\n")


def format_json(data: Any, pretty: bool = False) -> str:
    """Format data as JSON string.

    Args:
        data: Data to serialize as JSON.
        pretty: If True, output indented JSON for human readability.

    Returns:
        JSON string.
    """
    indent = 2 if pretty else None
    return json.dumps(data, indent=indent, default=str)
