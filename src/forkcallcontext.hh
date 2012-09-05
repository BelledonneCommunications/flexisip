/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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

#ifndef forkcallcontext_hh
#define forkcallcontext_hh

#include "agent.hh"
#include "event.hh"
#include "transaction.hh"
#include "forkcontext.hh"
#include <list>

class ForkCallContext: public ForkContext {
private:
	std::shared_ptr<ResponseSipEvent> mBestResponse;
	int mFinal;
	bool mCancelled;
	std::list<int> mForwardResponses;

public:
	ForkCallContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, std::shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener);
	virtual bool hasFinalResponse();
	~ForkCallContext();
	virtual void onNew(const std::shared_ptr<IncomingTransaction> &transaction);
	virtual void onRequest(const std::shared_ptr<IncomingTransaction> &transaction, std::shared_ptr<RequestSipEvent> &event);
	virtual void onDestroy(const std::shared_ptr<IncomingTransaction> &transaction);
	virtual void onNew(const std::shared_ptr<OutgoingTransaction> &transaction);
	virtual void onResponse(const std::shared_ptr<OutgoingTransaction> &transaction, std::shared_ptr<ResponseSipEvent> &event);
	virtual void onDestroy(const std::shared_ptr<OutgoingTransaction> &transaction);
	virtual void checkFinished();
private:
	void cancel();
	void cancelOthers(const std::shared_ptr<OutgoingTransaction> &transaction = std::shared_ptr<OutgoingTransaction>());
	void decline(const std::shared_ptr<OutgoingTransaction> &transaction, std::shared_ptr<ResponseSipEvent> &ev);
	void forward(const std::shared_ptr<SipEvent> &ev, bool force = false);
	void store(std::shared_ptr<ResponseSipEvent> &ev);
};

#endif //forkcallcontext_hh
