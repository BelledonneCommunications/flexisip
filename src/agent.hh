#ifndef agent_hh
#define agent_hh

#include <list>
#include <string>

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/nta_stateless.h>

#include <common.hh>

class Transaction{
	public:
		Transaction(sip_t *request);
		~Transaction();
		bool matches(sip_t *sip);
		void setUserPointer(void *up);
		void *getUserPointer()const;
	private:
		su_home_t mHome;
		sip_from_t *mFrom;
		sip_from_t *mTo;
		sip_cseq_t *mCseq;
		void *mUser;
};

class Agent{
	public:
		Agent(su_root_t *root, const char *locaddr, int port);
		~Agent();
		virtual int onIncomingMessage(msg_t *msg, sip_t *sip);
		virtual int onRequest(msg_t *msg, sip_t *sip);
		virtual int onResponse(msg_t *msg, sip_t *sip);
		Transaction *createTransaction(sip_t *request);
		Transaction *findTransaction(sip_t *sip);
		void deleteTransaction(Transaction* t);
	private:
		nta_agent_t *mAgent;
		std::list<Transaction*> mTransactions;
		std::string mLocAddr;
		int mPort;
		static int messageCallback(nta_agent_magic_t *context, nta_agent_t *agent,msg_t *msg,sip_t *sip);
};

#endif

