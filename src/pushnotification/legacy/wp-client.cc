/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <openssl/err.h>

#include <flexisip/logmanager.hh>

#include <cJSON.h>
#include <utils/uri-utils.hh>

#include "microsoftpush.hh"
#include "wp-client.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

ClientWp::ClientWp(std::unique_ptr<Transport>&& transport,
                   const std::string& name,
                   unsigned maxQueueSize,
                   const std::string& packageSID,
                   const std::string& applicationSecret,
                   const Service* service)
    : LegacyClient{std::move(transport), name, maxQueueSize, service}, mPackageSID{packageSID},
      mApplicationSecret{applicationSecret} {
}

void ClientWp::retrieveAccessToken() {
	mAccessToken = "";
	mTokenExpiring = 0;

	SLOGD << "Retrieving windows phone push notification client access token...";

	// we must retrieve our access token

	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	BIO* bio;
	SSL* ssl = NULL;
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	const char* hostname = "login.live.com:443";

	bio = BIO_new_ssl_connect(ctx);
	BIO_set_conn_hostname(bio, hostname);
	/* Set the SSL_MODE_AUTO_RETRY flag */
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	SSL_set_options(ssl, SSL_OP_ALL);

	int sat = BIO_do_connect(bio);

	std::ostringstream buffer;
	std::ostringstream httpBody;
	ostringstream httpHeader;

	if (sat <= 0) {
		SLOGE << "Error attempting to connect to " << hostname << ": " << sat << " - " << strerror(errno);
		goto error;
	} else if ((sat = BIO_do_handshake(bio)) <= 0) {
		SLOGE << "Error attempting to handshake to " << hostname << ": " << sat << " - " << strerror(errno);
		goto error;
	}

	// we must retrieve our access token
	httpBody << "grant_type=client_credentials";
	httpBody << "&client_id=" << UriUtils::escape(mPackageSID, UriUtils::httpQueryKeyValReserved);
	httpBody << "&client_secret=" << UriUtils::escape(mApplicationSecret, UriUtils::httpQueryKeyValReserved);
	httpBody << "&scope="
	         << "notify.windows.com";

	httpHeader << "POST /accesstoken.srf HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: "
	           << hostname << "\r\nContent-Length: " << httpBody.str().size() << "\r\n\r\n";

	buffer << httpHeader.str() << httpBody.str();

	SLOGD << "Sending POST request:\n" << buffer.str();

	if ((sat = BIO_write(bio, buffer.str().data(), buffer.str().size())) <= 0) {
		SLOGE << "Write failed: " << sat;
		goto error;
	}

	char r[1024];
	sat = BIO_read(bio, r, sizeof(r) - 1);
	if (sat > 0) {
		r[sat] = 0;
		string responsestr(r, sat);

		if (responsestr.find("HTTP/1.1 200 OK") == 0) {
			string json = responsestr.substr(responsestr.find('{'));
			cJSON* root = cJSON_Parse(json.c_str());
			if (!root) {
				SLOGE << "Error parsing JSON response: " << cJSON_GetErrorPtr();
				return;
			}
			cJSON* access_token = cJSON_GetObjectItem(root, "access_token");
			cJSON* expires_in = cJSON_GetObjectItem(root, "expires_in");

			if (access_token && expires_in) {
				SLOGD << "Got access token which expires in " << expires_in->valueint;
				mAccessToken = access_token->valuestring;
				mTokenExpiring = time(0) + expires_in->valueint;
			} else {
				SLOGE << "Oops cannot retrieve access_token or expires_in:\n" << responsestr;
			}
		} else {
			SLOGE << "Unexpected server response:\n" << responsestr;
		}
	} else {
		SLOGE << "Cannot retrieve access_token:" << sat;
		goto error;
	}
	return;

error:
	ERR_print_errors_fp(stderr);
	if (bio) {
		BIO_free_all(bio);
	}
	if (ctx) {
		SSL_CTX_free(ctx);
	}
}

void ClientWp::sendPush(const std::shared_ptr<Request>& req) {
	if (time(0) > mTokenExpiring) {
		this->retrieveAccessToken();
	}
	if (mTokenExpiring != 0) {
		// we must add the authorization token
		auto req2 = static_cast<MicrosoftRequest*>(req.get());
		req2->createHTTPRequest(mAccessToken);
		return LegacyClient::sendPush(req);
	} else {
		SLOGD << "Cannot send push since we do not access token yet";
	}
}

} // namespace pushnotification
} // namespace flexisip
