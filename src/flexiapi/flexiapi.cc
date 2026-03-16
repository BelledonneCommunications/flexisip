/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "flexiapi.hh"

#include <filesystem>

using namespace std;
using namespace flexisip;
using namespace flexiapi;
using namespace nlohmann;

FlexiApi::FlexiApi(RestClient&& restClient, const std::string& apiPrefix)
    : mRestClient(std::move(restClient)),
      mApiPrefix{filesystem::path{"/" + apiPrefix + "/."}.lexically_normal().string()} {}

std::string FlexiApi::toApiPath(const string& methodPath) const {
	return mApiPrefix + methodPath;
}

void FlexiApi::resolveByUri(const ApiFormattedUri& sipUri,
                            const OnResponseCb& onResponseCb,
                            const OnErrorCb& onErrorCb) {
	mRestClient.get(toApiPath("resolve/"s + string{sipUri}), onResponseCb, onErrorCb);
}

void FlexiApi::accountSearchByUri(const ApiFormattedUri& sipUri,
                                  const OnResponseCb& onResponseCb,
                                  const OnErrorCb& onErrorCb) {
	mRestClient.get(toApiPath("accounts/"s + string{sipUri} + "/search"), onResponseCb, onErrorCb);
}

void FlexiApi::slotCreationByAccountId(int accountId,
                                       const SlotCreation& slotCreation,
                                       const OnResponseCb& onResponseCb,
                                       const OnErrorCb& onErrorCb) {
	mRestClient.post(toApiPath("accounts/"s + to_string(accountId) + "/voicemails"), slotCreation, onResponseCb,
	                 onErrorCb);
}

void FlexiApi::uploadVoicemail(const sofiasip::Url& uploadUrl,
                               const std::string& filePath,
                               const std::string& fileContent,
                               const OnResponseCb& onResponseCb,
                               const OnErrorCb& onErrorCb) {
	const HttpHeaders partHeader{
	    {"Content-Disposition", R"(form-data; name="file"; filename=")" + filePath + "\""},
	    {"Content-Type", "audio/wav"},
	};
	const http::MultiPartForm form{{partHeader, fileContent}};

	const auto path = uploadUrl.getPath();
	mRestClient.post(!path.empty() ? "/" + path : "", form, onResponseCb, onErrorCb);
}