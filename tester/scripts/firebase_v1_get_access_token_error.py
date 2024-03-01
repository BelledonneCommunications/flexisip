#!/usr/bin/env python3

"""
Always return an error, for testing purposes.
"""

try:

    import sys
    import json
    import warnings as warnlib

except BaseException as exception:

    print(f'{{"state": "ERROR", "data": {{"message": "{exception}"}}, "warnings": {[]}}}')
    sys.exit(0)

if __name__ == "__main__":
    with warnlib.catch_warnings(record=True) as warnings:
        warnlib.simplefilter("always")

        data = {
            "state": "ERROR",
            "data": {
                "message": "stub-message",
            },
            "warnings": [f"{warning.message}" for warning in warnings],
        }
        print(json.dumps(data))
