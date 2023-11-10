#!/usr/bin/env python3

"""
Always successfully execute, for testing purposes.
"""

try:

    import sys
    import json
    import time
    import datetime

except BaseException as exception:

    print(f'{{"state": "ERROR", "data": {{"message": "{exception}", "type": "IMPORT"}}}}')
    exit(0)


class FakeCredentials:

    def __init__(self) -> None:
        self.token = "TOKEN-" + str(time.time())
        self.expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=42)


if __name__ == "__main__":

    credentials = FakeCredentials()

    data = {
        "state": "SUCCESS",
        "data": {
            "token": credentials.token,
            "lifetime": int(credentials.expiry.timestamp()) - int(datetime.datetime.utcnow().timestamp())
        }
    }
    
    print(json.dumps(data))