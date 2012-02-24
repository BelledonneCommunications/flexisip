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


#ifndef forkcallstore_hh
#define forkcallstore_hh

#include "agent.hh"
#include "event.hh"
#include <list>
#include <map>

class ForkCallContext {
	Agent *agent;
	Module *module;
	IncomingTransaction *incoming;
	std::list<OutgoingTransaction *> outgoings;

	enum State {
		INITIAL,
		INVITED,
		RINGING,
	} state;

public:
	ForkCallContext(Agent * agent, Module *module);
	~ForkCallContext();

	void setIncomingTransaction(IncomingTransaction *transaction);
	void addOutgoingTransaction(OutgoingTransaction *transaction);
	void receiveInvite(IncomingTransaction *transaction);
	void receiveOk(OutgoingTransaction *transaction);
	void receiveCancel(IncomingTransaction *transaction);
	void receiveTimeout(OutgoingTransaction *transaction);
	void receiveTerminated(OutgoingTransaction *transaction);
	void receiveDecline(OutgoingTransaction *transaction);
	void receiveRinging(OutgoingTransaction *transaction);
	void receiveBye(IncomingTransaction *transaction);
private:
	void deleteTransaction(OutgoingTransaction *transaction);
	void deleteTransaction(IncomingTransaction *transaction);

};

class ForkCallStore {
	std::map<long, ForkCallContext*> mForkCallContexts;

public:
	ForkCallStore();
	~ForkCallStore();
	void addForkCall(long id, ForkCallContext* forkcall);
	ForkCallContext* getForkCall(long id);
	void removeForkCall(long id);
};

#endif //forkcallstore_hh
