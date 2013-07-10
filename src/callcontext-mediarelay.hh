/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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
	class RelaySessionTransaction {
	public:
		RelaySessionTransaction() :
			mRelaySession(std::shared_ptr<RelaySession>()) {

		}

		std::shared_ptr<RelaySession> mRelaySession;
		std::map<std::shared_ptr<Transaction>, std::shared_ptr<RelayChannel>> mTransactions;
		std::map<std::string, std::shared_ptr<RelayChannel>> mRelayChannels;
	};
	typedef enum {
		DUPLEX, FORWARD
	} RTPDir;
	static const int sMaxSessions = 4;
	RelayedCall(MediaRelayServer *server, sip_t *sip, RTPDir dir);
	
	/* Create a channel for each sdp media using defined relay ip for front and back. The transaction
	 * allow use to identify the callee (we don't have a tag yet).
	 */
	void initChannels(SdpModifier *m, const std::string &tag, const std::shared_ptr<Transaction> &transaction, const std::pair<std::string,std::string> &frontRelayIps, const std::pair<std::string,std::string> &backRelayIps);

	/* Change the ip/port of sdp line by provided ones. Used for masquerade front channels */
	void masqueradeForFront(int mline, std::string *ip, int *port);

	/* Change the ip/port of sdp line by provided ones for ICE. Used for masquerade front channels */
	void masqueradeIceForFront(int mline, std::string *ip, int *port);

	/* Change the ip/port of sdp line by provided ones. Used for masquerade back channels */
	void masqueradeForBack(int mline, std::string *ip, int *port, const std::string &tag, const std::shared_ptr<Transaction> &transaction);

	/* Change the ip/port of sdp mline by provided ones for ICE. Used for masquerade back channels */
	void masqueradeIceForBack(int mline, std::string *ip, int *port, const std::string &tag, const std::shared_ptr<Transaction> &transaction);

	/* Assign destination ip/port of front channel by provided ones of SDP. */
	void assignFrontChannel(SdpModifier *m, int mline, const std::string &ip, int port);

	/* Assign destination ip/port of front channel by provided ones of SDP. */
	void assignBackChannel(SdpModifier *m, int mline, const std::string &ip, int port, const std::string &tag, const std::shared_ptr<Transaction> &transaction);

	/* Set only one sender to the caller. */
	void update();

	/* Validate the channels using a transaction. After this functions the callee will be identified by
	 * the tag and not the transaction */
	void validateTransaction(const std::string &tag, const std::shared_ptr<Transaction> &transaction);

	/* Remove a back channel using its tag */
	bool removeBack(const std::string &tag);
	
	/* Remove a back channel using its transaction */
	bool removeTransaction(const std::shared_ptr<Transaction> &transaction);

	/* Set a back as unique channel. Remove all other channels and set the channel bidirectional. */
	void setUniqueBack(const std::string &tag);

	bool checkMediaValid();
	bool isInactive(time_t cur);
	std::shared_ptr<RelayChannel> getMS(int mline, std::string tag, const std::shared_ptr<Transaction> &transaction);

	virtual ~RelayedCall();

	void configureRelayChannel(std::shared_ptr<RelayChannel> ms,sip_t *sip, sdp_session_t *session, int mline_nr);

	/*Enable filtering of H264 Iframes for low bandwidth.*/
	void enableH264IFrameFiltering(int bandwidth_threshold, int decim);
	/*Enable telephone-event dropping for tls clients*/
	void enableTelephoneEventDrooping(bool value);
	
private:
	typedef enum {
		Idle, Initialized, Running
	} State;
	RelaySessionTransaction mSessions[sMaxSessions];
	MediaRelayServer *mServer;
	State mState;
	RTPDir mEarlymediaRTPDir;
	int mBandwidthThres;
	int mDecim;
	bool mDropTelephoneEvents;
};


#endif


