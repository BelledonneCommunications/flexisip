#!/usr/bin/env python3

"""
Always return an error, for testing purposes.
"""

try:

    import sys
    import json

except BaseException as exception:

    print(f'{{"state": "ERROR", "data": {{"message": "{exception}", "type": "IMPORT"}}}}')
    exit(0)


if __name__ == "__main__":
    data = {
        "state": "ERROR",
        "data": {
            "message": "this is a sample error message for testing purposes",
            "type": "TEST"
        }
    }

    print(json.dumps(data))