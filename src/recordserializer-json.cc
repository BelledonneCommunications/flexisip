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

#include "recordserializer.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexisip/logmanager.hh"
#include "registrar/extended-contact.hh"

using namespace std;
using namespace flexisip;

using json = nlohmann::json;

static json normalizeKeys(const json& j) {
	json normalized;
	for (auto it = j.begin(); it != j.end(); ++it) {
		normalized[string_utils::toLower(it.key())] = it.value();
	}
	return normalized;
}

bool RecordSerializerJson::parse(string_view str, Record& r) {
	if (str.empty()) return true;
	json root{};
	try {
		root = json::parse(str);
	} catch (const json::parse_error& e) {
		LOGE << "Error while parsing JSON contact (" << e.what() << ")";
		return false;
	}
	try {
		// The access to the item must be case-insensitive
		root = normalizeKeys(root);
		int itemId = 0;
		for (auto& jsonData : root.at("contacts")) {
			jsonData = normalizeKeys(jsonData);
			const string sipContact{jsonData["contact"]};
			if (sipContact.empty()) throw invalid_argument("missing SIP contact URI");
			const string callId{jsonData["call-id"]};
			if (callId.empty()) throw invalid_argument("missing call-id");
			const time_t expireAt{jsonData["expires-at"]};
			const time_t updateTime{jsonData["update-time"]};
			const int cseq{jsonData["cseq"]};

			// Optional attributes
			const bool alias{static_cast<bool>(jsonData.value<int>("alias", 0))};
			const list<string> acceptHeaders{jsonData["accept"].cbegin(), jsonData["accept"].cend()};
			const string userAgent{jsonData.value<string>("user-agent", "")};
			const float q{jsonData.value<float>("q", 1.0)};
			const string lineValue{jsonData.value<string>("unique-id", "")};
			const list<string> stlpath{jsonData["path"].cbegin(), jsonData["path"].cend()};

			ExtendedContactCommon ec(stlpath, callId, lineValue);
			r.update(ec, sipContact.c_str(), expireAt, updateTime, q, cseq, alias, acceptHeaders, false, nullptr);

			if (r.count() < itemId + 1) {
				LOGE << "Cannot update record for contact " << sipContact;
				return false;
			}
			r.getExtendedContacts().latest()->get()->mUserAgent = userAgent;
			if (jsonData.contains("q")) {
				const auto currentQ = r.getExtendedContacts().latest()->get()->mQ;
				if (currentQ != q) {
					LOGW << "Priority parameter q in contact is not updated to given value (" << q
					     << "), keep current one (" << currentQ << ")";
				}
			}
			itemId++;
		}
	} catch (const json::parse_error& e) {
		LOGE << "Error while parsing JSON contact (" << e.what() << ")";
		return false;
	} catch (const json::type_error& e) {
		LOGE << "Error while getting data from JSON contact (" << e.what() << ")";
		return false;
	} catch (const exception& e) {
		LOGE << "Error while getting JSON contact (" << e.what() << ")";

		return false;
	}

	return true;
}

bool RecordSerializerJson::serialize(const Record& r, string& serialized, bool log) {

	nlohmann::json root{};
	root["contacts"] = nlohmann::json::array();
	for (const auto& ec : r.getExtendedContacts()) {
		nlohmann::json jsonContact{};
		jsonContact["contact"] = ExtendedContact::urlToString(ec->mSipContact->m_url);
		jsonContact["expires-at"] = ec->getSipExpireTime();
		jsonContact["q"] = ec->mQ;
		jsonContact["unique-id"] = ec->mKey.str();
		jsonContact["user-agent"] = ec->getUserAgent();
		jsonContact["call-id"] = ec->callId();
		jsonContact["cseq"] = ec->mCSeq;
		jsonContact["alias"] = ec->mAlias ? 1 : 0;
		jsonContact["update-time"] = ec->getRegisterTime();
		jsonContact["path"] = ec->mPath;
		jsonContact["accept"] = ec->mAcceptHeader;
		root["contacts"].push_back(jsonContact);
	}
	serialized = root.dump(1, '\t');
	if (serialized.empty()) return false;
	if (log) LOGI << "Serialized contact: " << serialized;
	return true;
}