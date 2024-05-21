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

#include "callcontext-mediarelay.hh"

#include <array>
#include <memory>
#include <string>

#include "sofia-sip/su_types.h"

#include "h264iframefilter.hh"
#include "mediarelay.hh"
#include "module-toolbox.hh"
#include "utils/cast-to-const.hh"

using namespace std;
using namespace flexisip;

RelayedCall::RelayedCall(const shared_ptr<MediaRelayServer>& server, sip_t* sip)
    : CallContextBase(sip), mServer(server), mBandwidthThres(0) {
	LOGD("New RelayedCall %p", this);
	mDropTelephoneEvents = false;
	mIsEstablished = false;
	mEarlyMediaRelayCount = 0;
}

/* Enable filtering of H264 Iframes for low bandwidth. */
void RelayedCall::enableH264IFrameFiltering(int bandwidth_threshold, int decim, bool onlyIfLastProxy) {
	mBandwidthThres = bandwidth_threshold;
	mDecim = decim;
	mH264DecimOnlyIfLastProxy = onlyIfLastProxy;
}

void RelayedCall::enableTelephoneEventDrooping(bool value) {
	mDropTelephoneEvents = value;
}

void RelayedCall::setupSpecificRelayTransport(RelayTransport* rt, const char* destHost) {
	Agent* agent = mServer->getAgent();
	auto relayIps = agent->getPreferredIp(destHost);
	bool isIpv6 = strchr(relayIps.first.c_str(), ':') != nullptr;
	if (isIpv6) {
		rt->mIpv6Address = relayIps.first;
		rt->mIpv6BindAddress = relayIps.second;
		rt->mPreferredFamily = AF_INET6;
	} else {
		rt->mIpv4Address = relayIps.first;
		rt->mIpv4BindAddress = relayIps.second;
		rt->mPreferredFamily = AF_INET;
	}
}

void RelayedCall::initChannels(const std::shared_ptr<SdpModifier>& sdpModifier,
                               const std::string& tag,
                               const std::string& trid,
                               const string& fromHost,
                               const string& destHost) {
	sdp_media_t* mediaLine = sdpModifier->mSession->sdp_media;
	sdp_connection_t* global_c = sdpModifier->mSession->sdp_connection;
	int i = 0;
	bool hasMultipleTargets = false;
	Agent* agent = mServer->getAgent();

	int maxEarlyRelays = mServer->mModule->mMaxRelayedEarlyMedia;
	if (maxEarlyRelays != 0) {
		if (ModuleToolbox::getCustomHeaderByName(sdpModifier->mSip, "X-Target-Uris")) {
			hasMultipleTargets = true;
		}
	}

	for (i = 0; mediaLine != NULL && i < sMaxSessions; mediaLine = mediaLine->m_next, ++i) {
		if (mediaLine->m_port == 0) {
			// case of declined mline.
			continue;
		}
		if (i >= sMaxSessions) {
			LOGE("Max sessions per relayed call is reached.");
			return;
		}
		shared_ptr<RelaySession> s = mSessions[i];

		sdp_connection_t* connectionLine = mediaLine->m_connections ? mediaLine->m_connections : global_c;
		bool isIpv6 = connectionLine && connectionLine->c_addrtype == sdp_addr_ip6;
		bool hasIce = sdp_attribute_find(mediaLine->m_attributes, "candidate") != nullptr;

		RelayTransport rt;

		rt.mIpv6Address = agent->getResolvedPublicIp(true);
		rt.mIpv4Address = agent->getResolvedPublicIp(false);
		rt.mIpv6BindAddress = agent->getRtpBindIp(true);
		rt.mIpv4BindAddress = agent->getRtpBindIp(false);
		rt.mPreferredFamily = (!rt.mIpv6Address.empty() && isIpv6) ? AF_INET6 : AF_INET;
		rt.mDualStackRequired = hasIce && !rt.mIpv6Address.empty();

		if (s == NULL) {
			/* We initialize here the RelaySession for the current mline, passing the IP addresses we have to use
			 * to exchange with the caller. */

			if ((connectionLine && connectionLine->c_address &&
			     strcmp(connectionLine->c_address, fromHost.c_str()) == 0) &&
			    !hasIce && !mForcePublicAddressEnabled) {
				/* The client is not natted or knows its public IP address. In this case we trust him
				 * and propose a relay address that exactly matches its network.
				 * This is needed for a flexisip that runs on a multi-homed machine. */
				setupSpecificRelayTransport(&rt, connectionLine->c_address);
			} else {
				/* The client is very likely behind a nat and doesn't know its public ip address.
				 * In that case, we provide him with a relay address that is the public address of the proxy,
				 * but with the same address family as the address in the c= line of the SDP*/
			}
			s = mServer->createSession(tag, rt);
			mSessions[i] = s;
		}
		shared_ptr<RelayChannel> chan = s->getChannel("", trid);
		if (chan == NULL) {
			/* We complete the RelaySession by adding a branch (to a callee instance). However we have no information
			 * about which IP family it will use, as we don't have yet its SDP answer at this stage. As fallback
			 * solution, we examine the host part of the request uri of the caller to "guess" whether it is under an
			 * IPv6 network or not. This is clearly not reliable, however remember that trick is useful and necessary
			 * only for clients that don't use ICE. In a general way, ICE is the only way to solve media connectivity
			 * issues between two clients. */
			isIpv6 = strchr(destHost.c_str(), ':') != nullptr;
			rt.mPreferredFamily = isIpv6 ? AF_INET6 : AF_INET;

			if (!hasIce && !mForcePublicAddressEnabled) setupSpecificRelayTransport(&rt, destHost.c_str());
			/*this is a new outgoing branch to be established*/
			chan = s->createBranch(trid, rt, hasMultipleTargets);
		}
	}
}

MasqueradeContextPair RelayedCall::getMasqueradeContexts(int sessionId,
                                                         const std::string& offererTag,
                                                         const std::string& offeredTag,
                                                         const std::string& trid) {
	if (sessionId >= sMaxSessions)
		return MasqueradeContextPair(shared_ptr<SdpMasqueradeContext>(), shared_ptr<SdpMasqueradeContext>());
	shared_ptr<RelaySession> s = mSessions[sessionId];
	if (s == NULL) {
		return MasqueradeContextPair(shared_ptr<SdpMasqueradeContext>(), shared_ptr<SdpMasqueradeContext>());
	}
	auto offerer = s->getChannel(offererTag, "");
	auto offered = s->getChannel(offeredTag, trid);
	return MasqueradeContextPair(static_pointer_cast<SdpMasqueradeContext>(offerer),
	                             static_pointer_cast<SdpMasqueradeContext>(offered));
}

bool RelayedCall::checkMediaValid() {
	for (int sessionId = 0; sessionId < sMaxSessions; ++sessionId) {
		shared_ptr<RelaySession> s = mSessions[sessionId];
		if (s && !s->checkChannels()) return false;
	}
	return true;
}

/* Obtain the local address and port used for relaying */
const RelayTransport*
RelayedCall::getChannelSources(int sessionId, const std::string& partyTag, const std::string& trId) {
	if (sessionId >= sMaxSessions) {
		return nullptr;
	}
	shared_ptr<RelaySession> s = mSessions[sessionId];
	if (s != NULL) {
		shared_ptr<RelayChannel> chan = s->getChannel(partyTag, trId);
		if (chan == NULL) {
			LOGW("RelayedCall::getChannelSources(): no channel");
		} else {
			return &chan->getRelayTransport();
		}
	}
	return nullptr;
}

/* Obtain destination (previously set by setChannelDestinations()*/
std::tuple<string, int, int>
RelayedCall::getChannelDestinations(int sessionId, const std::string& partyTag, const std::string& trId) {
	if (sessionId >= sMaxSessions) {
		return make_tuple("", 0, 0);
	}
	shared_ptr<RelaySession> s = mSessions[sessionId];
	if (s != NULL) {
		shared_ptr<RelayChannel> chan = s->getChannel(partyTag, trId);
		if (chan) return make_tuple(chan->getRemoteIp(), chan->getRemoteRtpPort(), chan->getRemoteRtcpPort());
	}
	return make_tuple("", 0, 0);
}

void RelayedCall::setChannelDestinations(const shared_ptr<SdpModifier>& sdpModifier,
                                         int sessionId,
                                         const string& ip,
                                         int rtp_port,
                                         int rtcp_port,
                                         const string& partyTag,
                                         const string& trId,
                                         bool isEarlyMedia) {
	if (sessionId >= sMaxSessions) return;

	const auto s = mSessions[sessionId];
	if (s == nullptr) return;

	// Default direction is SendRecv.
	auto dir = RelayChannel::SendRecv;
	const bool isEarlyMediaState = isEarlyMedia && !mIsEstablished && mServer->mModule->mEarlyMediaRelaySingle;

	// Make sure that only one device can send media to the caller (caller POV: receive media from only one callee),
	// until the call is established.
	if (isEarlyMediaState && sessionId == 0 /* and is first media session */) {

		// The device associated to the current transaction receives "SendRecv" capabilities. However, only one
		// transaction must have such capabilities. Thus, we set the direction to "SendOnly" for all media sessions
		// associated to the transaction that currently has the lead : mSendRecvTrId.
		for (const auto& session : mSessions) {
			if (session == nullptr) break; // sentinel reached
			
			if (const auto& channel = session->getChannel("", mSendRecvTrId))
				channel->setDirection(RelayChannel::SendOnly);
		}

		mSendRecvTrId = trId;
	}

	auto chan = s->getChannel(partyTag, trId);
	if (chan == NULL) {
		LOGW("RelayedCall::setChannelDestinations(): no channel");
		return;
	}

	if (chan->getRelayTransport().mRtpPort > 0) {

		if (isEarlyMedia) {
			int maxEarlyRelays = mServer->mModule->mMaxRelayedEarlyMedia;
			if (maxEarlyRelays != 0) {
				if (chan->hasMultipleTargets()) {
					/*joker: we cannot be limited by the max number of early media streams.
					 This is to preserve the possibility for the remote proxy to
					 distribute early media.
					 Finally, we wish that only adjacent clients are counted.
					 */
				} else if (s->getActiveBranchesCount() >= maxEarlyRelays) {
					LOGW("Maximum number of relayed early media streams reached for RelayedCall [%p]", this);
					dir = RelayChannel::Inactive;
				}
			}
		}
		configureRelayChannel(chan, sdpModifier->mSip, sdpModifier->mSession, sessionId);
		/* We don't want to update the destination address of this Channel when ICE has completed, because in this
		 * case the destination address set by the client in the c= line and port in m= lines is the relay address
		 * itself, because it is set like this for the other party. Flexisip is no longer in the loop and just has
		 * to keep the relay open in case it is necessary.
		 */
		if (chan->getState() != SdpMasqueradeContext::IceCompleted) {
			chan->setRemoteAddr(ip, rtp_port, rtcp_port, dir);
		}
	}
}

void RelayedCall::setEstablished(const string& trId) {
	int i;
	mIsEstablished = true;
	for (i = 0; i < sMaxSessions; ++i) {
		shared_ptr<RelaySession> s = mSessions[i];
		if (s) {
			s->setEstablished(trId);
		}
	}
}

void RelayedCall::removeBranch(const string& trId) {
	int i;

	for (i = 0; i < sMaxSessions; ++i) {
		shared_ptr<RelaySession> s = mSessions[i];
		if (s) {
			s->removeBranch(trId);
		}
	}
}

time_t RelayedCall::getLastActivity() {
	time_t maxtime = 0;
	shared_ptr<RelaySession> r;
	for (int i = 0; i < sMaxSessions; ++i) {
		time_t tmp;
		r = mSessions[i];
		if (r && ((tmp = r->getLastActivityTime()) > maxtime)) maxtime = tmp;
	}
	return MAX(maxtime, CallContextBase::getLastActivity());
}

void RelayedCall::terminate() {
	int i;
	for (i = 0; i < sMaxSessions; ++i) {
		shared_ptr<RelaySession> s = mSessions[i];
		if (s) {
			s->unuse();
			mSessions[i].reset();
		}
	}
}

RelayedCall::~RelayedCall() {
	LOGD("Destroy RelayedCall %p", this);
	terminate();
}

#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED

static bool isTls(url_t* url) {
	if (url->url_type == url_sips) return true;
	char transport[20] = {0};
	if (url_param(url->url_params, "transport", transport, sizeof(transport) - 1) > 0 &&
	    strcasecmp(transport, "tls") == 0)
		return true;
	return false;
}
#endif

static bool isLastProxy(Agent* ag, sip_t* sip) {
	sip_record_route_t* rr = sip->sip_record_route;
	if (!rr) {
		LOGE("No record-route in response handled by media-relay, should never happen");
		return false;
	}
	if (ag->isUs(rr->r_url)) {
		LOGD("We are last proxy of the call flow.");
		return true;
	}
	return false;
}

void RelayedCall::configureRelayChannel(shared_ptr<RelayChannel> ms,
                                        sip_t* sip,
                                        sdp_session_t* session,
                                        int sessionId) {
	sdp_media_t* mediaLine;
	int i;
	for (i = 0, mediaLine = session->sdp_media; i < sessionId; mediaLine = mediaLine->m_next, ++i) {
	}
	if (mBandwidthThres > 0) {
		if (mediaLine->m_type == sdp_media_video) {
			if (mediaLine->m_rtpmaps && strcmp(mediaLine->m_rtpmaps->rm_encoding, "H264") == 0) {
				sdp_bandwidth_t* b = session->sdp_bandwidths;
				if (b && ((int)b->b_value) <= (int)mBandwidthThres) {
					bool enabled = false;
					if (sip->sip_request == NULL) {
						// for responses, we want to activate the feature only if we are the last proxy.
						enabled = mH264DecimOnlyIfLastProxy ? isLastProxy(mServer->getAgent(), sip) : true;
					} else enabled = true;
					if (enabled) {
						LOGI("Enabling H264 filtering for channel %p", ms.get());
						ms->setFilter(make_shared<H264IFrameFilter>(mDecim));
					}
				}
			}
		}
	}
#ifdef MEDIARELAY_SPECIFIC_FEATURES_ENABLED
	if (mDropTelephoneEvents) {
		// only telephone event coming from tls clients are dropped.
		if (mline->m_type == sdp_media_audio) {
			if (sip->sip_contact == NULL || sip->sip_contact->m_url == NULL || isTls(sip->sip_contact->m_url)) {
				sdp_rtpmap_t* rtpmap;
				for (rtpmap = mline->m_rtpmaps; rtpmap != NULL; rtpmap = rtpmap->rm_next) {
					if (strcasecmp(rtpmap->rm_encoding, "telephone-event") == 0) {
						LOGI("Enabling telephone-event filtering on payload type %i", rtpmap->rm_pt);
						ms->setFilter(make_shared<TelephoneEventFilter>((int)rtpmap->rm_pt));
					}
				}
			}
		}
	}
#endif
}

const std::array<std::shared_ptr<const RelaySession>, RelayedCall::sMaxSessions>& RelayedCall::getSessions() const {
	return castToConst(mSessions);
}
