#!/usr/bin/env python3

"""
Always successfully execute, for testing purposes.
"""

try:

    import sys
    import json
    import time
    import datetime
    import warnings as warnlib

except BaseException as exception:

    print(f'{{"state": "ERROR", "data": {{"message": "{exception}"}}, "warnings": {[]}}}')
    sys.exit(0)


class FakeCredentials:

    def __init__(self) -> None:
        self.token = "stub-token-" + str(time.time())
        self.expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=42)


if __name__ == "__main__":
    with warnlib.catch_warnings(record=True) as warnings:
        warnlib.simplefilter("always")

        credentials = FakeCredentials()

        data = {
            "state": "SUCCESS",
            "data": {
                "token": credentials.token,
                "lifetime": int(credentials.expiry.timestamp()) - int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            },
            "warnings": [f"{warning.message}" for warning in warnings],
        }
        print(json.dumps(data))
