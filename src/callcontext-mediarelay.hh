/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "callstore.hh"
#include "mediarelay.hh"
#include "sdp-modifier.hh"
#include <map>
#include <memory>
#include <string>
#include <tuple>

namespace flexisip {

class TranscodedCall;

class RelayedCall : public CallContextBase {
public:
	static const int sMaxSessions = 4;
	RelayedCall(const std::shared_ptr<MediaRelayServer>& server, sip_t* sip);

	void forcePublicAddress(bool force) {
		mForcePublicAddressEnabled = force;
	}

	/* Create a channel for each sdp media using defined relay ip for front and back. The transaction
	 * allow use to identify the callee (we don't have a tag yet).
	 */
	void initChannels(const std::shared_ptr<SdpModifier>& sdpModifier,
	                  const std::string& tag,
	                  const std::string& trid,
	                  const std::string& from_host,
	                  const std::string& destHost);

	/* Obtain the masquerade contexts for given sessionId. The trid is used when offeredTag is not yet defined.*/
	MasqueradeContextPair getMasqueradeContexts(int sessionId,
	                                            const std::string& offererTag,
	                                            const std::string& offeredTag,
	                                            const std::string& trid);

	/* Obtain the local addresses and ports used for relaying. May return nullptr in case of invalid usage (such as
	 * invalid trId or partyTag)*/
	const RelayTransport* getChannelSources(int sessionId, const std::string& partyTag, const std::string& trId);

	/* Obtain destination (previously set by setChannelDestinations()*/
	std::tuple<std::string, int, int>
	getChannelDestinations(int sessionId, const std::string& partyTag, const std::string& trId);

	void setChannelDestinations(const std::shared_ptr<SdpModifier>& sdpModifier,
	                            int sessionId,
	                            const std::string& ip,
	                            int rtp_port,
	                            int rtcp_port,
	                            const std::string& partyTag,
	                            const std::string& trId,
	                            bool isEarlyMedia);

	void removeBranch(const std::string& trId);
	void setEstablished(const std::string& trId);

	bool checkMediaValid();
	virtual time_t getLastActivity();
	void terminate();

	virtual ~RelayedCall();

	void configureRelayChannel(std::shared_ptr<RelayChannel> chan, sip_t* sip, sdp_session_t* session, int sessionId);

	/*Enable filtering of H264 Iframes for low bandwidth.*/
	void enableH264IFrameFiltering(int bandwidth_threshold, int decim, bool onlyIfLastProxy);
	/*Enable telephone-event dropping for tls clients*/
	void enableTelephoneEventDrooping(bool value);
	const std::shared_ptr<MediaRelayServer>& getServer() const {
		return mServer;
	}

	const std::array<std::shared_ptr<const RelaySession>, sMaxSessions>& getSessions() const;

private:
	void setupSpecificRelayTransport(RelayTransport* rt, const char* destHost);
	std::array<std::shared_ptr<RelaySession>, sMaxSessions> mSessions;
	const std::shared_ptr<MediaRelayServer>& mServer;
	int mBandwidthThres;
	int mDecim;
	int mEarlyMediaRelayCount;
	bool mH264DecimOnlyIfLastProxy;
	bool mDropTelephoneEvents;
	bool mIsEstablished;
	bool mForcePublicAddressEnabled = false;
	std::string mSendRecvTrId{};
};

} // namespace flexisip