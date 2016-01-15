/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#ifndef callcontext_mediarelay_hh
#define callcontext_mediarelay_hh

#include "callstore.hh"
#include <memory>
#include <string>
#include "mediarelay.hh"
#include "sdp-modifier.hh"
#include <map>



class TranscodedCall;

class RelayedCall: public CallContextBase {
public:
	static const int sMaxSessions = 4;
	RelayedCall(const shared_ptr<MediaRelayServer> &server, sip_t *sip);

	/* Create a channel for each sdp media using defined relay ip for front and back. The transaction
	 * allow use to identify the callee (we don't have a tag yet).
	 */
	void initChannels(const shared_ptr<SdpModifier> &m, const std::string &tag, const std::string &trid, const std::pair<std::string,std::string> &frontRelayIps, const std::pair<std::string,std::string> &backRelayIps);

	/* Obtain the local address and port used for relaying */
	std::pair<std::string,int> getChannelSources(int mline, const std::string & partyTag, const std::string &trId);

	/* Obtain destination (previously set by setChannelDestinations()*/
	std::pair<std::string,int> getChannelDestinations(int mline, const std::string & partyTag, const std::string &trId);

	void setChannelDestinations(const shared_ptr<SdpModifier> &m, int mline, const std::string &ip, int port, const std::string & partyTag, const std::string &trId,
		bool isEarlyMedia);

	void removeBranch(const std::string &trId);
	void setEstablished(const std::string &trId);

	bool checkMediaValid();
	bool isInactive(time_t cur);
	void terminate();

	virtual ~RelayedCall();

	void configureRelayChannel(std::shared_ptr<RelayChannel> chan,sip_t *sip, sdp_session_t *session, int mline_nr);

	/*Enable filtering of H264 Iframes for low bandwidth.*/
	void enableH264IFrameFiltering(int bandwidth_threshold, int decim, bool onlyIfLastProxy);
	/*Enable telephone-event dropping for tls clients*/
	void enableTelephoneEventDrooping(bool value);
	const shared_ptr<MediaRelayServer> & getServer()const{
		return mServer;
	}
private:
	std::shared_ptr<RelaySession> mSessions[sMaxSessions];
	const shared_ptr<MediaRelayServer> & mServer;
	int mBandwidthThres;
	int mDecim;
	int mEarlyMediaRelayCount;
	bool mH264DecimOnlyIfLastProxy;
	bool mDropTelephoneEvents;
	bool mHasSendRecvBack;
	bool mIsEstablished;
};


#endif


