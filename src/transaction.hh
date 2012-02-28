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

#include <sofia-sip/msg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>


class Transaction;
typedef void (*TransactionCallback) (const sip_t *sip, Transaction *transaction);

class StatefulSipEvent;
class Transaction {
protected:
	void* magic;
	TransactionCallback callback;

public:
	Transaction(TransactionCallback callback, void *magic = NULL) :
		magic(magic), callback(callback) {
	};
	void* getMagic() {
		return magic;
	}
	virtual StatefulSipEvent *create(msg_t * msg, sip_t *sip) = 0;
	virtual void send(StatefulSipEvent *) = 0;
	virtual ~Transaction() {
	}
	;
};

class OutgoingTransaction: public Transaction {
private:
	nta_outgoing_t *outgoing;
	nta_agent_t *agent;

public:
	OutgoingTransaction(nta_agent_t *agent, msg_t * msg, sip_t *sip, TransactionCallback callback, void *magic);
	~OutgoingTransaction();
	StatefulSipEvent *create(msg_t * msg, sip_t *sip);
	void send(StatefulSipEvent *);
	nta_outgoing_t* getOutgoing();

private:
	static int _callback(nta_outgoing_magic_t *magic, nta_outgoing_t *irq, const sip_t *sip);
};

class IncomingTransaction: public Transaction {
private:
	nta_incoming_t *incoming;
	nta_agent_t *agent;

public:
	IncomingTransaction(nta_agent_t *agent, msg_t * msg, sip_t *sip, TransactionCallback callback, void *magic);
	~IncomingTransaction();
	StatefulSipEvent *create(msg_t * msg, sip_t *sip);
	void send(StatefulSipEvent *);
	nta_incoming_t* getIncoming();

private:
	static int _callback(nta_incoming_magic_t *magic, nta_incoming_t *irq, const sip_t *sip);
};

#endif //transaction_hh
