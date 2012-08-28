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

#ifndef forkcontext_hh
#define forkcontext_hh

#include "agent.hh"
#include "event.hh"
#include "transaction.hh"

class ForkContext {
protected:
	Agent * mAgent;
	std::shared_ptr<RequestSipEvent> mEvent;
	std::shared_ptr<IncomingTransaction> mIncoming;
	std::list<std::shared_ptr<OutgoingTransaction>> mOutgoings;
	
public:
	ForkContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event);
	virtual bool hasFinalResponse(){return false;};
	virtual ~ForkContext();
	virtual void onNew(const std::shared_ptr<IncomingTransaction> &transaction);
	virtual void onRequest(const std::shared_ptr<IncomingTransaction> &transaction, std::shared_ptr<RequestSipEvent> &event) = 0;
	virtual bool onDestroy(const std::shared_ptr<IncomingTransaction> &transaction);
	virtual void onNew(const std::shared_ptr<OutgoingTransaction> &transaction);
	virtual void onResponse(const std::shared_ptr<OutgoingTransaction> &transaction, std::shared_ptr<ResponseSipEvent> &event) = 0;
	virtual bool onDestroy(const std::shared_ptr<OutgoingTransaction> &transaction);
	const std::shared_ptr<RequestSipEvent> &getEvent();
};

#endif /* forkcontext_hh */
