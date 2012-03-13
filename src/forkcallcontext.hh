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
#include <list>
#include <map>

class ForkCallContext: public IncomingTransactionHandler, public OutgoingTransactionHandler {
	Agent *mAgent;
	std::shared_ptr<IncomingTransaction> mIncoming;
	std::list<std::shared_ptr<OutgoingTransaction>> mOutgoings;
	std::shared_ptr<MsgSip> mBestResponse;
	int mFinal;
	int m2xxMaxForwards;

public:
	ForkCallContext(Agent *agent);
	~ForkCallContext();
	void onNew(const std::shared_ptr<IncomingTransaction> &transaction);
	void onEvent(const std::shared_ptr<IncomingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event);
	void onDestroy(const std::shared_ptr<IncomingTransaction> &transaction);
	void onNew(const std::shared_ptr<OutgoingTransaction> &transaction);
	void onEvent(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event);
	void onDestroy(const std::shared_ptr<OutgoingTransaction> &transaction);
private:
	void cancel();
	void closeOthers(const std::shared_ptr<OutgoingTransaction> &transaction);
	void decline(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<MsgSip> &ms);
	void forward(const std::shared_ptr<MsgSip> &ms, bool force = false);
	void store(const std::shared_ptr<MsgSip> &ms);
};

#endif //forkcallcontext_hh
