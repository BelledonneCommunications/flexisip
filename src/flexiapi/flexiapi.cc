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

#include "config.hh"
#include "endpoints.hh"
#include "flexiapi/schemas/voicemail/slot-creation-json.hh"

using namespace std;
using namespace flexisip;
using namespace flexiapi;
using namespace nlohmann;

FlexiApi::FlexiApi(RestClient&& restClient, const std::optional<std::chrono::milliseconds> criticalTimeout)
    : mRestClient(std::move(restClient)), mCriticalTimeout(criticalTimeout) {}

void FlexiApi::resolveByUri(const ApiFormattedUri& sipUri,
                            const OnResponseCb& onResponseCb,
                            const OnErrorCb& onErrorCb,
                            const Criticality criticality) {
	mRestClient.get(endpoints::resolveUri(sipUri), onResponseCb, onErrorCb,
	                criticality == Criticality::kCritical ? mCriticalTimeout : nullopt);
}

void FlexiApi::accountSearchByUri(const ApiFormattedUri& sipUri,
                                  const OnResponseCb& onResponseCb,
                                  const OnErrorCb& onErrorCb,
                                  const Criticality criticality) {
	mRestClient.get(endpoints::accountSearch(sipUri), onResponseCb, onErrorCb,
	                criticality == Criticality::kCritical ? mCriticalTimeout : nullopt);
}

void FlexiApi::slotCreationByAccountId(int accountId,
                                       const SlotCreation& slotCreation,
                                       const OnResponseCb& onResponseCb,
                                       const OnErrorCb& onErrorCb,
                                       const Criticality criticality) {
	mRestClient.post(endpoints::voicemailSlotCreation(accountId), slotCreation, onResponseCb, onErrorCb,
	                 criticality == Criticality::kCritical ? mCriticalTimeout : nullopt);
}

void FlexiApi::uploadVoicemail(const sofiasip::Url& uploadUrl,
                               const std::string& filePath,
                               const std::string& fileContent,
                               const OnResponseCb& onResponseCb,
                               const OnErrorCb& onErrorCb,
                               const Criticality criticality) {
	const HttpHeaders partHeader{
	    {"Content-Disposition", R"(form-data; name="file"; filename=")" + filePath + "\""},
	    {"Content-Type", "audio/wav"},
	};
	const http::MultiPartForm form{{partHeader, fileContent}};

	const auto path = uploadUrl.getPath();
	mRestClient.post(!path.empty() ? "/" + path : "", form, onResponseCb, onErrorCb,
	                 criticality == Criticality::kCritical ? mCriticalTimeout : nullopt);
}