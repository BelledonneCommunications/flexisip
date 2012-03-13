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

#ifndef transaction_hh
#define transaction_hh

#include "agent.hh"
#include "event.hh"
#include <sofia-sip/msg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>

class OutgoingTransaction;
class IncomingTransaction;

class IncomingTransactionHandler {
public:
	virtual void onNew(const std::shared_ptr<IncomingTransaction> &transaction) = 0;
	virtual void onEvent(const std::shared_ptr<IncomingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) = 0;
	virtual void onDestroy(const std::shared_ptr<IncomingTransaction> &transaction) = 0;
	virtual ~IncomingTransactionHandler() {
	}
};

class OutgoingTransactionHandler {
public:
	virtual void onNew(const std::shared_ptr<OutgoingTransaction> &transaction) = 0;
	virtual void onEvent(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) = 0;
	virtual void onDestroy(const std::shared_ptr<OutgoingTransaction> &transaction) = 0;
	virtual ~OutgoingTransactionHandler() {
	}
};

class Transaction {
protected:
	Agent *mAgent;

public:
	Transaction(Agent *agent) :
		mAgent(agent) {
	}

	Agent * getAgent() {
		return mAgent;
	}

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) = 0;
	virtual void send(const std::shared_ptr<MsgSip> &msg) = 0;

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) = 0;
	virtual ~Transaction() {

	}
};

class OutgoingTransaction: public Transaction, public std::enable_shared_from_this<OutgoingTransaction> {
public:
	OutgoingTransaction(Agent *agent, const std::shared_ptr<OutgoingTransactionHandler> &handler);
	void cancel();
	~OutgoingTransaction();
private:
	nta_outgoing_t *mOutgoing;
	std::shared_ptr<OutgoingTransactionHandler> mHandler;

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);

private:
	static int _callback(nta_outgoing_magic_t *magic, nta_outgoing_t *irq, const sip_t *sip);
};

class IncomingTransaction: public Transaction, public std::enable_shared_from_this<IncomingTransaction> {
public:
	IncomingTransaction(Agent *agent, const std::shared_ptr<IncomingTransactionHandler> &handler);
	void handle(const std::shared_ptr<MsgSip> &ms);
	std::shared_ptr<MsgSip> createResponse(int status, char const *phrase);
	~IncomingTransaction();
private:
	nta_incoming_t *mIncoming;
	std::shared_ptr<IncomingTransactionHandler> mHandler;

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);

private:
	static int _callback(nta_incoming_magic_t *magic, nta_incoming_t *irq, const sip_t *sip);
};

#endif //transaction_hh
