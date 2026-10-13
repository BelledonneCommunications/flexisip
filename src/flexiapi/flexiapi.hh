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

#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <string>

#include "flexiapi/schemas/api-formatted-uri.hh"
#include "flexiapi/schemas/voicemail/slot-creation.hh"
#include "flexisip/utils/http-url.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip::flexiapi {

class FlexiApi {
public:
	static constexpr std::string_view kFlexiApiPath{"/api/"};

	using OnErrorCb = HttpMessageContext::OnErrorCb;
	using OnResponseCb = HttpMessageContext::OnResponseCb;

	enum class Criticality {
		kNonCritical,
		kCritical,
	};

	explicit FlexiApi(RestClient&& restClient,
	                  const std::string& apiPrefix = kFlexiApiPath.data(),
	                  std::optional<std::chrono::milliseconds> criticalTimeout = std::nullopt);

	/********** Account/Group **********/
	void resolveByUri(const ApiFormattedUri& sipUri,
	                  const OnResponseCb& onResponseCb,
	                  const OnErrorCb& onErrorCb,
	                  Criticality criticality = Criticality::kNonCritical);
	void accountSearchByUri(const ApiFormattedUri& sipUri,
	                        const OnResponseCb& onResponseCb,
	                        const OnErrorCb& onErrorCb,
	                        Criticality criticality = Criticality::kNonCritical);

	/********** Voicemail **********/
	void slotCreationByAccountId(int accountId,
	                             const SlotCreation& slotCreation,
	                             const OnResponseCb& onResponseCb,
	                             const OnErrorCb& onErrorCb,
	                             Criticality criticality = Criticality::kNonCritical);
	void uploadVoicemail(const sofiasip::Url& uploadUrl,
	                     const std::string& filePath,
	                     const std::string& fileContent,
	                     const OnResponseCb& onResponseCb,
	                     const OnErrorCb& onErrorCb,
	                     Criticality criticality = Criticality::kNonCritical);

private:
	static constexpr std::string_view mLogPrefix{"FlexiApi"};

	std::string toApiPath(const std::string& methodPath) const;

	RestClient mRestClient;
	std::string mApiPrefix;
	std::optional<std::chrono::milliseconds> mCriticalTimeout;
};

class TimeCriticFlexiApi {
public:
	explicit TimeCriticFlexiApi(const std::shared_ptr<FlexiApi>& flexiApi) : mFlexiApi(flexiApi) {}

	void resolveByUri(const ApiFormattedUri& sipUri,
	                  const FlexiApi::OnResponseCb& onResponseCb,
	                  const FlexiApi::OnErrorCb& onErrorCb) const {
		mFlexiApi->resolveByUri(sipUri, onResponseCb, onErrorCb, FlexiApi::Criticality::kCritical);
	}

	void accountSearchByUri(const ApiFormattedUri& sipUri,
	                        const FlexiApi::OnResponseCb& onResponseCb,
	                        const FlexiApi::OnErrorCb& onErrorCb) const {
		mFlexiApi->accountSearchByUri(sipUri, onResponseCb, onErrorCb, FlexiApi::Criticality::kCritical);
	}

private:
	static constexpr std::string_view mLogPrefix{"TimeCriticFlexiApi"};

	std::shared_ptr<FlexiApi> mFlexiApi;
};

} // namespace flexisip::flexiapi