#!/usr/bin/env python3

#  Flexisip, a flexible SIP proxy server with media capabilities.
#  Copyright (C) 2010-2024 Belledonne Communications SARL.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.

"""
Retrieve a valid access token that can be used to authorize requests.
Lifetime is expressed in seconds.

All outputs of this script are printed in the standard output and formatted in JSON.
The structure is as follows: {"state": str ['ERROR', 'SUCCESS'], "data": obj, "warnings": list[str]}
	On success: data = {"token": str, "lifetime": int}
	On error:   data = {"message": str}
"""

import warnings as warnlib

warnlib.simplefilter("ignore")

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

	print('{{"state": "ERROR", "data": {{"message": "{exception}"}}, "warnings": []}}'.format(exception=exception))
	sys.exit(0)


class ScriptState:
	ERROR = "ERROR"
	SUCCESS = "SUCCESS"


def error(message, warnings):
	"""
	Print (in JSON format) the result of script execution in case of an error.

	:param message: error message
	:param warnings: list of warning messages
	"""
	payload = {
		"state": ScriptState.ERROR,
		"data": {
			"message": message,
		},
		"warnings": warnings,
	}
	print(json.dumps(payload))


def extract_warnings(warnings):
	"""
	Extract warning messages from a list of warnlib.WarningMessage.

	:param warnings: list of warnlib.WarningMessage objects
	:return: list of warning messages
	"""
	return ["{message}".format(message=warning.message) for warning in warnings]


SCOPES = ['https://www.googleapis.com/auth/firebase.messaging']

if __name__ == "__main__":

	with warnlib.catch_warnings(record=True) as warnings:
		warnlib.simplefilter("always")

		parser = argparse.ArgumentParser(
			prog="FirebaseV1 access token provider",
			description="Try to get Firebase OAuth2 access token for the given service account",
			epilog=""
		)
		parser.add_argument(
			"-f",
			"--filename",
			type=Path,
			dest="filename",
			help="path to the service account json file",
			required=True
		)
		arguments = parser.parse_args()

		if not arguments.filename.exists() or not arguments.filename.is_file():
			error_message = "path to service account json file is not valid ({filename})".format(
				filename=arguments.filename)
			error(error_message, extract_warnings(warnings))
			sys.exit(0)

		try:
			credentials = service_account.Credentials.from_service_account_file(arguments.filename, scopes=SCOPES)
			request = google.auth.transport.requests.Request()
			credentials.refresh(request)

			# Make expiry an offset-aware datetime.
			expiry = credentials.expiry.replace(tzinfo=datetime.timezone.utc)
			now = datetime.datetime.now(datetime.timezone.utc)
			lifetime = int((expiry - now).total_seconds())

			if lifetime <= 0:
				error_message = "computed token lifetime is negative or null ({lifetime}s) [now = {now}, expiry = {expiry}]".format(
					lifetime=lifetime, now=now, expiry=expiry)
				error(error_message, extract_warnings(warnings))
				sys.exit(0)

			data = {
				"state": ScriptState.SUCCESS,
				"data": {
					"token": credentials.token,
					"lifetime": lifetime,
				},
				"warnings": extract_warnings(warnings),
			}
			print(json.dumps(data))

		except SystemExit:
			pass

		except BaseException as exception:
			error("{exception}".format(exception=exception), extract_warnings(warnings))
