#!/usr/bin/env python3

"""
Always return the same token, for testing purposes.
"""

try:

    import sys
    import json
    import warnings as warnlib

except BaseException as exception:

    print(f'{{"state": "ERROR", "data": {{"message": "{exception}"}}, "warnings: {[]}}}')
    sys.exit(0)

if __name__ == "__main__":
    with warnlib.catch_warnings(record=True) as warnings:
        warnlib.simplefilter("always")

        # Voluntarily throw a warning.
        warnlib.warn("stub-warning-message", DeprecationWarning)

        data = {
            "state": "SUCCESS",
            "data": {
                "token": "stub-token",
                "lifetime": int(42),
            },
            "warnings": [f"{warning.message}" for warning in warnings],
        }
        print(json.dumps(data))
