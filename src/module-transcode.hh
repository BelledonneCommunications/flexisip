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

#include <algorithm>
#include <functional>
#include <vector>

#include <flexisip/module.hh>

#include "agent.hh"
#include "module-toolbox.hh"

#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif

#ifdef ENABLE_TRANSCODER
#include "callcontext-transcoder.hh"
#endif

namespace flexisip {

#ifdef ENABLE_TRANSCODER
class TickerManager {
public:
	TickerManager() : mLastTickerIndex(0), mStarted(false) {
	}
	MSTicker* chooseOne() {
		if (!mStarted) {
			int cpucount = ModuleToolbox::getCpuCount();
			mLastTickerIndex = 0;
			for (int i = 0; i < cpucount; ++i) {
				mTickers.push_back(ms_ticker_new());
			}
			mStarted = true;
		}
		if (mLastTickerIndex >= mTickers.size()) mLastTickerIndex = 0;
		return mTickers[mLastTickerIndex++];
	}
	~TickerManager() {
		for_each(mTickers.begin(), mTickers.end(), std::function{ms_ticker_destroy});
	}

private:
	std::vector<MSTicker*> mTickers;
	unsigned int mLastTickerIndex;
	bool mStarted;
};
#endif

class Transcoder : public Module {
	friend std::shared_ptr<Module> ModuleInfo<Transcoder>::create(Agent*);

public:
	~Transcoder();
	virtual void onLoad(const GenericStruct* module_config);
	virtual void onRequest(std::shared_ptr<RequestSipEvent>& ev);
	virtual void onResponse(std::shared_ptr<ResponseSipEvent>& ev);
	virtual void onIdle();

#ifdef ENABLE_TRANSCODER
	const std::list<const PayloadType*>& getSupportedPayloads() const;
#endif

private:
	Transcoder(Agent* ag, const ModuleInfoBase* moduleInfo);
#ifdef ENABLE_TRANSCODER
	TickerManager mTickerManager;
	int handleOffer(TranscodedCall* c, MsgSip& ms);
	int handleAnswer(TranscodedCall* c, MsgSip& ms);
	int processInvite(TranscodedCall* c, RequestSipEvent& ev);
	void process200OkforInvite(TranscodedCall* ctx, MsgSip& ms);
	void processAck(TranscodedCall* ctx, MsgSip& ms);
	bool processSipInfo(TranscodedCall* c, RequestSipEvent& ev);
	void onTimer();
	static void sOnTimer(void* unused, su_timer_t* t, void* zis);
	bool canDoRateControl(sip_t* sip);
	bool hasSupportedCodec(const std::list<PayloadType*>& ioffer);
	void normalizePayloads(std::list<PayloadType*>& l);
	std::list<PayloadType*> orderList(const std::list<std::string>& config, const std::list<PayloadType*>& l);
	std::list<PayloadType*> mSupportedAudioPayloads;
	CallStore mCalls;
	su_timer_t* mTimer;
	std::list<std::string> mRcUserAgents;
	MSFactory* mFactory;
	CallContextParams mCallParams;
	bool mRemoveBandwidthsLimits;
#endif
	static ModuleInfo<Transcoder> sInfo;
};

} // namespace flexisip