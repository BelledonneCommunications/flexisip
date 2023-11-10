#!/usr/bin/env python3

"""
Always return the same token, for testing purposes.
"""

try:

    import sys
    import json
    import time
    import datetime

except BaseException as exception:

    print(f'{{"state": "ERROR", "data": {{"message": "{exception}", "type": "IMPORT"}}}}')
    exit(0)

if __name__ == "__main__":
    data = {
        "state": "SUCCESS",
        "data": {
            "token": "THIS_IS_AN_ACCESS_TOKEN",
            "lifetime": int(42)
        }
    }
    print(json.dumps(data))
