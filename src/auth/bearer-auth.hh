/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include <list>
#include <optional>
#include <string>
#include <unordered_map>

#include <openssl/asn1.h>

#include "auth/auth-scheme.hh"
#include "flexisip/sofia-wrapper/auth-status.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"
#include "utils/transport/http/http1-client.hh"

namespace flexisip {

/**
 * Class that implements the bearer scheme.
 **/
class Bearer : public AuthScheme {
public:
	enum class PubKeyType {
		file,
		wellKnown,
	};

	struct BearerParams {
		sofiasip::Url issuer;
		std::string realm;
		std::string audience;
		std::list<std::string> scope;
		std::string idClaimer;
	};
	struct KeyStoreParams {
		PubKeyType keyType;
		std::string keyPath;
		std::chrono::milliseconds wellKnownRefreshDelay;
		std::chrono::milliseconds jwksRefreshDelay;
	};

	struct KeyInfo {
		std::string key;
		std::string algo;
		ASN1_TIME notAfter{};
	};

	Bearer(const std::shared_ptr<sofiasip::SuRoot>& root,
	       const BearerParams& params,
	       const KeyStoreParams& keyStoreParams);
	std::string schemeType() const override;
	void challenge(AuthStatus& as, const auth_challenger_t* ach) override;
	State check(const msg_auth_t* credentials, std::function<void(ChallengeResult&&)>&& onResult) override;
	void notifyPubKeyRequest();

private:
	void processPendingTokens();

	/**
	 * Class that downloads keys and cache them.
	 **/
	class KeyStore {
	public:
		enum class KeyCache { Required, Pending, Done };
		KeyStore(const std::shared_ptr<sofiasip::SuRoot>& root,
		         const sofiasip::Url& issuer,
		         const KeyStoreParams& params,
		         std::function<void()>&& refreshCallback);
		void askForJWKS();
		bool keyCachePending() {
			return mKeyCacheUpdate == KeyCache::Pending;
		}
		KeyInfo getPubKey(const std::string& kid) const;

	private:
		void onWellKnownResponse(std::string_view response);
		void askForWellKnown();
		void onJWKSResponse(std::string_view response);
		void updateKeys(const std::unordered_map<std::string, KeyInfo>& pubKeys);
		void checkKeysValidity();

		KeyCache mKeyCacheUpdate{KeyCache::Required};
		PubKeyType mKeyType;
		std::unordered_map<std::string, KeyInfo> mPubKeys;
		sofiasip::Url mIssuer;
		std::string mWellKnownUrl;
		std::string mKeyPath;
		Http1Client mHttpClient;
		sofiasip::Timer mWellKnownTimer;
		sofiasip::Timer mJWKSTimer;
		std::function<void()> mOnPubKeyRefresh;
	};
	struct PendingToken {
		std::string token;
		std::string kid;
		bool retry;
		ChallengeResult result;
		std::function<void(ChallengeResult&&)> callback;
	};

	BearerParams mParams;
	std::list<PendingToken> mPendingTokens;
	KeyStore mKeyStore;
};
} // namespace flexisip
