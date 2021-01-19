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

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <regex>

#include <sofia-sip/url.h>

namespace flexisip {
namespace pushnotification {

/* Apple pn-provider may be 'apns' or 'apns.dev' */
static const std::regex sApplePnProviderRegex("apns|apns\\.dev");

/*
   pn-param:
   * all the characters before the first point are taken as the team ID;
   * all the characters between the first and the last point are taken as the bundle ID
	 and may contains points;
   * all the characters after the last point are taken as the service type. It may be
	 'voip' or 'remote' or 'voip&remote' if the application needs the two kinds of
	 push notification.
*/
static const std::regex sPnParamRegex("([^.]+)\\.(.+)\\.((?:voip|remote|&)+)");

/*
   Regex to use for extracting information from 'pn-prid' parameter when only one token has been
   given by the user agent. All the characters or all the characters before ':' are taken as
   the token. Characters after ':' must be 'voip' or 'remote'. Column character isn't authorized
   in the token.
*/
static const std::regex sPnPridOneTokenRegex("([^:]+)(?::(voip|remote))?");

/*
   Regex to use for extracting information from 'pn-prid' parameter when several tokens have been
   given by the user agent. 'pn-prid' value must be formated as '<token>:<service>' where
   <token> may be contains any characters except ':' and <service> is equal to 'remote' or 'voip'.
*/
static const std::regex sPnPridMultipleTokensRegex("([^:]+):(voip|remote)");


enum class ApplePushType : std::uint8_t {
	Unknown,
	Pushkit,
	RemoteBasic,
	RemoteWithMutableContent,
	Background
};

std::string toString(ApplePushType type) noexcept;

struct RFC8599PushParams {
	std::string pnProvider{};
	std::string pnPrid{};
	std::string pnParam{};
};

class PushInfo {
public:
	enum class Event : std::uint8_t { Call, Message , Refer };

	Event mEvent{Event::Message}; // Event to advertise: call or text message.
	std::string mType{}; // type of push notif: apple, google, wp
	std::string mAppId{}; // app id, as extracted from Contact
	std::string mDeviceToken{}; // device token, as extracted from Contact
	std::string mApiKey{}; // api key (magic number required for Google)
	std::string mAlertSound{}; // sound to play
	std::string mAlertMsgId{}; // ID of message to show to user
	std::string mFromName{}; // From's display name
	std::string mFromUri{}; // From's SIP uri
	std::string mFromTag{}; // From tag
	std::string mToUri{};   // To SIP uri
	std::string mCallId{};  // CallID
	std::string mText{};	// Text of the chat message.
	std::string mUid{}; // The unique id as used in the ExtendedContact, if available.
	std::string mAccessToken{}; // access token required by Microsoft to authenticate our server
	std::string mTeamId{}; // The Apple team id
	std::string mChatRoomAddr{}; // In case of a chat room invite, the sip addr of the chat room is needed. (ios specific).
	std::string mCustomPayload{};
	int mTtl{0}; //Time to live of the push notification.
	ApplePushType mApplePushType{ApplePushType::Unknown};
	bool mNoBadge{false}; // Whether to display a badge on the application (ios specific).

	/*
	 * Tells whether "180 Ringing" should be replied by the proxy instead of "110 Push sent".
	 * Practically only Apple RemoteBasic and RemoteWithMutableContent pushes need to have
	 * 180 replied because they doesn't wake the application up immediately.
	 */
	bool needRinging() const noexcept {
		// because
		return (mEvent == Event::Call || mEvent == Event::Refer)
			&& (mApplePushType == ApplePushType::RemoteBasic || mApplePushType == ApplePushType::RemoteWithMutableContent);
	}
	
	// Will throw if some of the RFC8599PushParams values are not supported or do not match the expected format
	void readRFC8599PushParams(const RFC8599PushParams &params);
};

class Request {
	public:
		enum class State{
			NotSubmitted,
			InProgress,
			Successful,
			Failed
		};

		template <typename T, typename U>
		Request(T &&appid, U &&type) : mAppId(std::forward<T>(appid)), mType(std::forward<U>(type)) {}
		Request(const Request &) = delete;
		Request(Request &&) = delete;
		virtual ~Request() = default;

		Request &operator=(const Request &src) = delete;
		Request &operator=(Request &&src) = delete;

		State getState() const noexcept {return mState;}
		void setState(State state) noexcept {mState = state;}

		const std::string &getAppIdentifier() const noexcept {return mAppId;}
		const std::string &getType() const noexcept {return mType;}

		virtual const std::vector<char> &getData() = 0;
		virtual std::string isValidResponse(const std::string &str) = 0;
		virtual bool isServerAlwaysResponding() = 0;

	protected:
		std::string quoteStringIfNeeded(const std::string &str) const noexcept;
		std::string getPushTimeStamp() const noexcept;

	private:
		State mState{State::NotSubmitted};
		const std::string mAppId;
		const std::string mType;

};

} // pushnotification namespace
} // flexisip namespace
