#!/usr/bin/env python3

"""
Always output unexpected data, for testing purposes.
"""

try:

    import sys
    import json

except BaseException as exception:

    print(f'{{"state": "ERROR", "data": {{"message": "{exception}"}}, "warnings: {[]}}}')
    sys.exit(0)

if __name__ == "__main__":
    data = {
        "stub-key": "stub-value",
    }
    print(json.dumps(data))
