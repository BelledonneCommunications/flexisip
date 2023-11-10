#!/usr/bin/env python3

#  Flexisip, a flexible SIP proxy server with media capabilities.
#  Copyright (C) 2010-2023 Belledonne Communications SARL.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Retrieve a valid access token that can be used to authorize requests.

All outputs of this script are printed in the standard output and formatted in JSON.
The structure is as follows: {"state": str ['ERROR', 'SUCCESS'], "data": obj}
    On success: data = {"token": str, "lifetime": int}
    On error:   data = {"message": str, "type": str ['IMPORT', 'FIREBASE', 'SCRIPT']}
"""

try:
    import sys
    import json
    import datetime
    import argparse
    from pathlib import Path
    
    # https://github.com/googleapis/google-auth-library-python
    import google.auth.transport.requests
    from google.oauth2 import service_account

except BaseException as exception:

    print(f'{{"state": "ERROR", "data": {{"message": "{exception}", "type": "IMPORT"}}}}')
    exit(0)


class ScriptState:
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"


class ErrorType:
    SCRIPT = "SCRIPT"
    FIREBASE = "FIREBASE"


def error(message: str, type: str) -> None:

    data = {
        "state": ScriptState.ERROR,
        "data": {
            "message": message,
            "type": type
        }
    }
    print(json.dumps(data))


SCOPES = ['https://www.googleapis.com/auth/firebase.messaging']


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        prog="FirebaseV1 access token provider",
        description="Try to get Firebase OAuth2 access token for the given service account",
        epilog=""
    )

    parser.add_argument("-f", "--filename", type=Path, dest="filename", help="path to the service account json file", required=True)
    arguments = parser.parse_args()

    if not arguments.filename.exists() or not arguments.filename.is_file():
        error(f"path to service account json file is not valid ({arguments.filename})", ErrorType.SCRIPT)
        sys.exit(0)

    try:
        
        credentials = service_account.Credentials.from_service_account_file(arguments.filename, scopes=SCOPES)
        request = google.auth.transport.requests.Request()
        credentials.refresh(request)

        data = {
            "state": ScriptState.SUCCESS,
            "data": {
                "token": credentials.token,
                "lifetime": int(credentials.expiry.timestamp()) - int(datetime.datetime.utcnow().timestamp())
            }
        }
        print(json.dumps(data))

    except BaseException as exception:

        error(f"{exception}", ErrorType.FIREBASE)
        sys.exit(0)