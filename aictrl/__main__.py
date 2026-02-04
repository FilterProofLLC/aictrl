"""Allow running aictrl as a module: python -m aictrl"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
