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
			mRelaySession(NULL) {

		}

		RelaySession *mRelaySession;
		std::map<std::shared_ptr<Transaction>, std::shared_ptr<MediaSource>> mTransactions;
		std::map<std::string, std::shared_ptr<MediaSource>> mMediaSources;
		bool toDelete;
	};
	typedef enum {
		DUPLEX, FORWARD
	} RTPDir;
	static const int sMaxSessions = 4;
	RelayedCall(MediaRelayServer *server, sip_t *sip, RTPDir dir);
	/*Enable filtering of H264 Iframes for low bandwidth.*/
	void enableH264IFrameFiltering(int bandwidth_threshold, int decim);
	/*this function is called to masquerade the SDP, for each mline*/
	void setMedia(SdpModifier *m, const std::string &tag, const std::shared_ptr<Transaction> &transaction, const std::string &frontIp, const std::string&backIp);

	void backwardTranslate(int mline, std::string *ip, int *port);

	void backwardIceTranslate(int mline, std::string *ip, int *port);

	void forwardTranslate(int mline, std::string *ip, int *port, const std::string &tag, const std::shared_ptr<Transaction> &transaction);

	void forwardIceTranslate(int mline, std::string *ip, int *port, const std::string &tag, const std::shared_ptr<Transaction> &transaction);

	void setFront(SdpModifier *m, int mline, const std::string &ip, int port);

	void setBack(SdpModifier *m, int mline, const std::string &ip, int port, const std::string &tag, const std::shared_ptr<Transaction> &transaction);

	// Set only one sender to the caller
	void update();

	void validTransaction(const std::string &tag, const std::shared_ptr<Transaction> &transaction);
	bool removeTransaction(const std::shared_ptr<Transaction> &transaction);

	bool removeBack(const std::string &tag);

	void validBack(const std::string &tag);

	bool checkMediaValid();
	bool isInactive(time_t cur);
	std::shared_ptr<MediaSource> getMS(int mline, std::string tag, const std::shared_ptr<Transaction> &transaction);

	virtual ~RelayedCall();

	void configureMediaSource(std::shared_ptr<MediaSource> ms, sdp_session_t *session, int mline_nr);

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
};


#endif


