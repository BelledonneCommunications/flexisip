/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <cstring>
#include <functional>
#include <regex>
#include <sstream>
#include <stdexcept>

#include <sofia-sip/sip_header.h>

#include "utils/string-utils.hh"
#include <flexisip/logmanager.hh>

#include "external-auth-module.hh"

using namespace std;

namespace flexisip {

ExternalAuthModule::ExternalAuthModule(su_root_t* root, const std::string& domain, int nonceExpire, bool qopAuth)
    : FlexisipAuthModuleBase(root, domain, nonceExpire, qopAuth) {
	mEngine = nth_engine_create(root, TPTAG_TLS_SNI(true), TAG_END());
}

ExternalAuthModule::~ExternalAuthModule() {
	nth_engine_destroy(mEngine);
}

void ExternalAuthModule::checkAuthHeader(FlexisipAuthStatus& as,
                                         msg_auth_t* credentials,
                                         auth_challenger_t const* ach) {
	auto ctx = make_unique<HttpRequestCtx>(*this, as, *ach, *credentials);
	pendingAuthRequests.push(std::move(ctx));
	as.status(100);

	if (!mWaitingForResponse) {
		popAndSendRequest();
	}
}

void ExternalAuthModule::popAndSendRequest() {
	auto ctx = std::move(pendingAuthRequests.front());
	pendingAuthRequests.pop();
	try {
		auto& externalAs = dynamic_cast<ExternalAuthModule::Status&>(ctx->as);
		auto& credentials = ctx->creds;
		HttpUriFormater::TranslationFunc func = [&externalAs, &credentials](const string& key) {
			return extractParameter(externalAs, credentials, key);
		};
		string uri = mUriFormater.format(func);

		nth_client_t* request =
		    nth_client_tcreate(mEngine, onHttpResponseCb, reinterpret_cast<nth_client_magic_t*>(ctx.get()),
		                       http_method_get, "GET", URL_STRING_MAKE(uri.c_str()), TAG_END());
		if (request == nullptr) {
			ostringstream os;
			os << "HTTP request for '" << uri << "' has failed";
			throw runtime_error{os.str()};
		}

		// Request successfully sent. Give the ownership of HttpRequestCtx to the HTTP client
		// and swtich to waiting state.
		ctx.release();
		mWaitingForResponse = true;
		SLOGD << "HTTP request [" << request << "] to '" << uri << "' successfully sent";

	} catch (const runtime_error& e) {
		SLOGE << e.what();
		onError(ctx->as);
		notify(ctx->as);
	}
}

void ExternalAuthModule::onHttpResponse(HttpRequestCtx& ctx, nth_client_t* request, const http_t* http) {
	shared_ptr<RequestSipEvent> ev;

	try {
		int sipCode = 0;
		string phrase;
		string reasonHeaderValue;
		string pAssertedIdentity;
		ostringstream os;

		if (http == nullptr) {
			os << "HTTP server responds with code " << nth_client_status(request);
			throw runtime_error(os.str());
		}

		auto status = http->http_status->st_status;
		auto httpBody = toString(http->http_payload);
		SLOGD << "HTTP response received [" << status << "]: " << endl << (!httpBody.empty() ? httpBody : "<empty>");
		if (status != 200) {
			os << "unhandled HTTP status code [" << status << "]";
			throw runtime_error(os.str());
		}

		if (httpBody.empty()) {
			os << "HTTP server answered with an empty body";
			throw runtime_error(os.str());
		}

		try {
			map<string, string> kv = parseHttpBody(httpBody);
			sipCode = stoi(kv["Status"]);
			phrase = std::move(kv["Phrase"]);
			reasonHeaderValue = std::move(kv["Reason"]);
			pAssertedIdentity = std::move(kv["P-Asserted-Identity"]);
		} catch (const logic_error& e) {
			os << "error while parsing HTTP body: " << e.what();
			throw runtime_error(os.str());
		}

		if (!validSipCode(sipCode)) {
			os << "invalid SIP code";
			throw runtime_error(os.str());
		}

		auto& httpAuthStatus = dynamic_cast<ExternalAuthModule::Status&>(ctx.as);
		httpAuthStatus.status(sipCode == 200 ? 0 : sipCode);
		httpAuthStatus.phrase(su_strdup(ctx.as.home(), phrase.c_str()));
		httpAuthStatus.reason(reasonHeaderValue);
		httpAuthStatus.pAssertedIdentity(pAssertedIdentity);
		if (sipCode == 401 || sipCode == 407) challenge(ctx.as, &ctx.ach);
	} catch (const runtime_error& e) {
		SLOGE << "HTTP request [" << request << "]: " << e.what();
		onError(ctx.as);
	} catch (...) {
		if (request) nth_client_destroy(request);
		throw;
	}
	notify(ctx.as);
	if (request) nth_client_destroy(request);
}

std::map<std::string, std::string> ExternalAuthModule::parseHttpBody(const std::string& body) const {
	istringstream is(body);
	ostringstream os;
	map<string, string> result;
	string line;

	do {
		getline(is, line);
		if (line.empty()) continue;

		auto column = find(line.cbegin(), line.cend(), ':');
		if (column == line.cend()) {
			os << "invalid line '" << line << "': missing column symbol";
			throw invalid_argument(os.str());
		}

		string& value = result[string(line.cbegin(), column)];
		auto valueStart = find_if_not(column + 1, line.cend(), [](const char& c) { return isspace(c) != 0; });
		if (valueStart == line.cend()) {
			os << "invalid line '" << line << "': missing value";
			throw invalid_argument(os.str());
		}

		value.assign(valueStart, line.cend());
	} while (!is.eof());
	return result;
}

std::string
ExternalAuthModule::extractParameter(const Status& as, const msg_auth_t& credentials, const std::string& paramName) {
	if (paramName.compare(0, 7, "header:") == 0) {
		string headerName(paramName, 7);
		if (!headerName.empty()) {
			char encodedHeader[255];
			msg_header_t* header = as.event()->getMsgSip()->findHeader(headerName, true);
			if (header) {
				cmatch m;
				sip_header_e(encodedHeader, sizeof(encodedHeader), reinterpret_cast<sip_header_t*>(header), 0);
				if (regex_match(encodedHeader, m, regex(".*:\\s*(.*)\r\n"))) {
					return m.str(1);
				}
			}
		}
	}

	for (int i = 0; credentials.au_params[i] != nullptr; i++) {
		const char* param = credentials.au_params[i];
		const char* equal = strchr(const_cast<char*>(param), '=');
		if (paramName.compare(0, paramName.size(), param, equal - param) == 0) {
			return StringUtils::strip(equal + 1, '"');
		}
	}

	if (paramName == "scheme") return StringUtils::strip(credentials.au_scheme, '"');
	if (paramName == "method") return StringUtils::strip(as.method(), '"');
	if (paramName == "from") return StringUtils::strip(as.fromHeader(), '"');
	if (paramName == "sip-instance") return StringUtils::strip(as.sipInstance(), '"');
	if (paramName == "uuid") return as.uuid();
	if (paramName == "domain") return StringUtils::strip(as.domain(), '"');

	return "null";
}

int ExternalAuthModule::onHttpResponseCb(nth_client_magic_t* magic,
                                         nth_client_t* request,
                                         const http_t* http) noexcept {
	// Get back the ownership to the HttpRequestCtx
	unique_ptr<HttpRequestCtx> ctx{reinterpret_cast<HttpRequestCtx*>(magic)};

	// The response has been received, switching back to idle state.
	ctx->am.mWaitingForResponse = false;

	ctx->am.onHttpResponse(*ctx, request, http);
	if (!ctx->am.pendingAuthRequests.empty()) {
		ctx->am.popAndSendRequest();
	}
	return 0;
}

std::string ExternalAuthModule::toString(const http_payload_t* httpPayload) {
	if (httpPayload == nullptr || httpPayload->pl_data == nullptr || httpPayload->pl_len == 0) {
		return string();
	}
	return string(httpPayload->pl_data, httpPayload->pl_len);
}

bool ExternalAuthModule::validSipCode(int sipCode) {
	const auto it = find(sValidSipCodes.cbegin(), sValidSipCodes.cend(), sipCode);
	return (it != sValidSipCodes.cend());
}

std::array<int, 4> ExternalAuthModule::sValidSipCodes{{200, 401, 407, 403}};

} // namespace flexisip
