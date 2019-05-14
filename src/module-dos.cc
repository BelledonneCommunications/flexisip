/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/module.hh>
#include <flexisip/agent.hh>
#include <flexisip/logmanager.hh>
#include "utils/threadpool.hh"
#include <sofia-sip/tport.h>
#include <sofia-sip/msg_addr.h>
#include <unordered_map>

using namespace std;
using namespace flexisip;

typedef struct DosContext {
	uint64_t recv_msg_count_since_last_check;
	double last_check_recv_msg_check_time;
	double packet_count_rate;
} DosContext;

class DoSProtection;

typedef struct BanContext {
	string ip;
	string port;
	string protocol;
	std::function<void(BanContext*)> lambda;
	su_timer_t *timer;
} BanContext;

class DoSProtection : public Module, ModuleToolbox {

  private:
	static ModuleInfo<DoSProtection> sInfo;
	int mTimePeriod;
	int mPacketRateLimit;
	int mBanTime;
	bool mIptablesVersionChecked;
	bool mIptablesSupportsWait;
	list<string> mWhiteList;
	unordered_map<string, DosContext> mDosContexts;
	unordered_map<string, DosContext>::iterator mDOSHashtableIterator;
	ThreadPool *mThreadPool;
	string mFlexisipChain;

	int runIptables(const string & arguments, bool ipv6=false, bool dumpErrors=true){
		ostringstream command;
		char output[512] = { 0 };
		
		command << (ipv6 ? "/sbin/ip6tables" : "/sbin/iptables");
		command << " " << arguments;
		command << " 2>&1";
		FILE *f = popen(command.str().c_str(), "r");
		if (f == nullptr){
			LOGE("DoSProtection: popen() failed: %s", strerror(errno));
			return -1;
		}
		size_t readCount = fread(output, 1, sizeof(output)-1, f);
		int ret = pclose(f);
		if (WIFEXITED(ret))
			ret = WEXITSTATUS(ret);
		if (ret != 0){
			if (dumpErrors){
				LOGE("DoSProtection: '%s' failed with output '%s'.", command.str().c_str(), output);
			}
		}
		if (ret == 0 || !dumpErrors) LOGD("DoSProtection: '%s' executed.", command.str().c_str());
		(void)readCount; // This variable is useless here, I know.
		return ret;
	}
	
	void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor configs[] = {
			{Integer, "time-period", "Number of milliseconds to consider to compute the packet rate", "3000"},
			{Integer, "packet-rate-limit", "Maximum packet rate in packets/seconds,  averaged over [time-period] "
										   "millisecond(s) to consider it as a DoS attack.",
			 "20"},
			{Integer, "ban-time", "Number of minutes to ban the ip/port using iptables", "2"},
			{String, "iptables-chain", "Name of the chain flexisip will create to store the banned IPs", "FLEXISIP"},
			config_item_end};
		module_config->get<ConfigBoolean>("enabled")->setDefault("true");
		module_config->addChildrenValues(configs);
	}

	void onLoad(const GenericStruct *mc) {
		mTimePeriod = mc->get<ConfigInt>("time-period")->read();
		mPacketRateLimit = mc->get<ConfigInt>("packet-rate-limit")->read();
		mBanTime = mc->get<ConfigInt>("ban-time")->read();
		mFlexisipChain = mc->get<ConfigString>("iptables-chain")->read();
		mDOSHashtableIterator = mDosContexts.begin();

		GenericStruct *cluster = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
		mWhiteList = cluster->get<ConfigStringList>("nodes")->read();
		for (auto it = mWhiteList.begin(); it != mWhiteList.end(); ++it) {
			const char *white_ip = (*it).c_str();
			LOGI("IP %s is in DOS protection white list", white_ip);
		}
		LOGI("IP 127.0.0.1 automatically added to DOS protection white list");

		tport_t *primaries = tport_primaries(nta_agent_tports(mAgent->getSofiaAgent()));
		if (primaries == NULL)
			LOGF("No sip transport defined.");
		for (tport_t *tport = primaries; tport != NULL; tport = tport_next(tport)) {
			tport_set_params(tport, TPTAG_DOS(mTimePeriod), TAG_END());
		}
		if (getuid() != 0) {
			LOGE("Flexisip not started with root privileges! iptables commands for DoS protection won't work.");
			return;
		}

		// Let's remove the Flexisip's chain in case the previous run crashed
		char iptables_cmd[512];
		
		// First we have to empty the chain, for ipv4
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -F %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
		if (runIptables(iptables_cmd) == 0) {
			// Then we have to remove the link to be able to remove the chain itself
			snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -t filter -D INPUT -j %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
			runIptables(iptables_cmd);

			snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -X %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
			runIptables(iptables_cmd);
		}
		// Same thing for IPv6
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -F %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
		if (runIptables(iptables_cmd, true) == 0) {
			// Then we have to remove the link to be able to remove the chain itself
			snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -t filter -D INPUT -j %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
			runIptables(iptables_cmd, true);

			snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -X %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
			runIptables(iptables_cmd, true);
		}

		// Now let's create it
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -N %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
		runIptables(iptables_cmd);
		runIptables(iptables_cmd, true);
		//Finally let's add a jump from the INPUT chain to ours
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -t filter -A INPUT -j %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
		runIptables(iptables_cmd);
		runIptables(iptables_cmd, true);
	}

	void onUnload() {
		// Let's remove the Flexisip's chain
		char iptables_cmd[512];
		// First we have to empty the chain
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -F %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
		runIptables(iptables_cmd);
		runIptables(iptables_cmd, true);

		// Then we have to remove the link to be able to remove the chain itself
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -t filter -D INPUT -j %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
		runIptables(iptables_cmd);
		runIptables(iptables_cmd, true);

		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -X %s", mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str());
		runIptables(iptables_cmd);
		runIptables(iptables_cmd, true);
	}

	virtual bool isValidNextConfig( const ConfigValue &value ) {
		GenericStruct *module_config = dynamic_cast<GenericStruct *>(value.getParent());
		if (!module_config->get<ConfigBoolean>("enabled")->readNext())
			return true;
		else {
#if __APPLE__
			LOGEN("DosProtection only works on linux hosts. Please disable this module.");
			return false;
#else
			if (!mIptablesVersionChecked) {
				mIptablesVersionChecked = true;
				if (runIptables("-w -V > /dev/null") == 0) {
					// iptables seems to support -w parameter required to allow concurrent usage of iptables
					mIptablesSupportsWait = true;
				}
				if (runIptables("-V > /dev/null", true) != 0) {
					LOGEN("ip6tables command is not installed. DoS protection is inactive for IPv6.");
				}
			}
			return true;
#endif
		}
	}

	void onIdle() {
		struct timeval now;
		double started_time_in_millis, time_elapsed;

		gettimeofday(&now, NULL);
		started_time_in_millis = now.tv_sec * 1000 + (now.tv_usec / 1000);

		if (mDOSHashtableIterator == mDosContexts.end()) {
			mDOSHashtableIterator = mDosContexts.begin();
		}
		for (; mDOSHashtableIterator != mDosContexts.end();) {
			double now_in_millis;
			DosContext dos = mDOSHashtableIterator->second;

			gettimeofday(&now, NULL);
			now_in_millis = now.tv_sec * 1000 + (now.tv_usec / 1000);
			time_elapsed = now_in_millis - dos.last_check_recv_msg_check_time;

			if (time_elapsed >= 3600 * 1000) { // If no message received in the past hour
				mDOSHashtableIterator = mDosContexts.erase(mDOSHashtableIterator);
			} else {
				++mDOSHashtableIterator;
			}

			if (now_in_millis - started_time_in_millis >= 100) { // Do not use more than 100ms to clean the hashtable
				LOGW("Started to clean dos hashtable %fms ago, let's stop for now a continue later",
					 now_in_millis - started_time_in_millis);
				break;
			}
		}
	}

	bool isIpWhiteListed(const char *ip) {
		if (!ip) return true; // If IP is null, is useless to try to add it in iptables...

		if (ip && strcmp(ip, "127.0.0.1") == 0) { // Never ban localhost, used for presence
			return true;
		}

		for (auto it = mWhiteList.begin(); it != mWhiteList.end(); ++it) { // Never ban ips from cluster
			const char *white_ip = (*it).c_str();
			if (white_ip && strcmp(ip, white_ip) == 0) {
				return true;
			}
		}
		return false;
	}

	void banIP(const char *ip, const char *port, const char *protocol) {
		char iptables_cmd[512];
		snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -C %s -p %s -s %s -m multiport --sports %s -j REJECT",
				 mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str(), protocol, ip, port);
		bool is_ipv6 = strchr(ip, ':') != nullptr;
		if (runIptables(iptables_cmd, is_ipv6, false) == 0) {
			LOGW("IP %s port %s on protocol %s is already in the iptables banned list, skipping...", ip, port, protocol);
		} else {
			snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -A %s -p %s -s %s -m multiport --sports %s -j REJECT",
				mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str(), protocol, ip, port);
			runIptables(iptables_cmd, is_ipv6);
		}
	}

	void unbanIP(BanContext *ctx) {
		string protocol = ctx->protocol;
		string ip = ctx->ip;
		string port = ctx->port;
		
		mThreadPool->Enqueue([&, protocol, ip, port] {
			char iptables_cmd[512];
			bool is_ipv6 = strchr(ip.c_str(), ':') != nullptr;
			snprintf(iptables_cmd, sizeof(iptables_cmd), "%s -D %s -p %s -s %s -m multiport --sports %s -j REJECT",
				mIptablesSupportsWait ? "-w" : "", mFlexisipChain.c_str(), protocol.c_str(), ip.c_str(), port.c_str());
			runIptables(iptables_cmd, is_ipv6);
		});
		delete ctx;
	}

	static void invokeLambdaFromSofiaTimerCallback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
		BanContext *ctx = (BanContext *)arg;
		su_timer_destroy(ctx->timer);
		ctx->timer = NULL;
		ctx->lambda(ctx);
	}

	void createBanContextAndPostInFuture(const char *ip, const char *port, const string &protocol) {
		BanContext *ctx = new BanContext();
		ctx->ip = ip;
		ctx->port = port;
		ctx->protocol = protocol;
		ctx->lambda = [&](BanContext *context) { unbanIP(context); };
		ctx->timer = su_timer_create(su_root_task(mAgent->getRoot()), 0);
		su_timer_set_interval(ctx->timer, invokeLambdaFromSofiaTimerCallback, ctx, mBanTime * 60 * 1000);
	}

	void onRequest(shared_ptr<RequestSipEvent> &ev) {
		shared_ptr<tport_t> inTport = ev->getIncomingTport();
		tport_t *tport = inTport.get();

		if (tport == NULL) {
			LOGE("Tport is null, can't check the packet count rate");
			return;
		}

		if (tport_is_udp(tport)) { // Sofia doesn't create a secondary tport for udp, so it will ban the primary and we
								   // don't want that
			shared_ptr<MsgSip> msg = ev->getMsgSip();
			MsgSip *msgSip = msg.get();
			su_sockaddr_t su[1];
			socklen_t len = sizeof su;
			sockaddr *addr = NULL;
			char ip[NI_MAXHOST], port[NI_MAXSERV];
			int err;

			msg_get_address(msgSip->getMsg(), su, &len);
			addr = &(su[0].su_sa);

			if ((err = getnameinfo(addr, len, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)) ==
				0) {
				string id = string(ip) + ":" + string(port);
				struct timeval now;
				DosContext &dosContext = mDosContexts[id];
				double now_in_millis, time_elapsed;

				dosContext.recv_msg_count_since_last_check++;
				gettimeofday(&now, NULL);
				now_in_millis = now.tv_sec * 1000 + (now.tv_usec / 1000);
				if (dosContext.last_check_recv_msg_check_time == 0) {
					dosContext.last_check_recv_msg_check_time = now_in_millis;
				}

				time_elapsed = now_in_millis - dosContext.last_check_recv_msg_check_time;
				if (time_elapsed < 0) {
					dosContext.packet_count_rate = 0;
					dosContext.recv_msg_count_since_last_check = 0;
					dosContext.last_check_recv_msg_check_time = now_in_millis;
				} else if (time_elapsed >= mTimePeriod) {
					dosContext.packet_count_rate = dosContext.recv_msg_count_since_last_check / time_elapsed * 1000;
					dosContext.recv_msg_count_since_last_check = 0;
					dosContext.last_check_recv_msg_check_time = now_in_millis;
				}

				if (dosContext.packet_count_rate >= mPacketRateLimit) {
					LOGW("Packet count rate (%f) >= limit (%i), blocking ip/port %s/%s on protocol udp for %i minutes",
						 dosContext.packet_count_rate, mPacketRateLimit, ip, port, mBanTime);
					if (!isIpWhiteListed(ip)) {
						mThreadPool->Enqueue([&, ip, port] { banIP(ip, port, "udp"); });
						createBanContextAndPostInFuture(ip, port, "udp");
						ev->terminateProcessing(); // the event is discarded
					} else {
						LOGW("IP %s should be banned but wasn't because in white list", ip);
					}
					dosContext.packet_count_rate = 0; // Reset it to not add the iptables rule twice by mistake
				}
			} else {
				LOGW("getnameinfo() failed: %s", gai_strerror(err));
			}
		} else {
			unsigned long packet_count_rate = tport_get_packet_count_rate(tport);
			if (packet_count_rate >= (unsigned long) mPacketRateLimit) {
				sockaddr *addr = tport_get_address(tport)->ai_addr;
				socklen_t len = tport_get_address(tport)->ai_addrlen;
				char ip[NI_MAXHOST], port[NI_MAXSERV];
				int err;

				if ((err = getnameinfo(addr, len, ip, sizeof(ip), port, sizeof(port),
									   NI_NUMERICHOST | NI_NUMERICSERV)) == 0) {
					LOGW("Packet count rate (%lu) >= limit (%i), blocking ip/port %s/%s on protocol tcp for %i minutes",
						 packet_count_rate, mPacketRateLimit, ip, port, mBanTime);
					if (!isIpWhiteListed(ip)) {
						mThreadPool->Enqueue([&, ip, port] { banIP(ip, port, "tcp"); });
						createBanContextAndPostInFuture(ip, port, "tcp");
						ev->terminateProcessing(); // the event is discarded
					} else {
						LOGW("IP %s should be banned but wasn't because in white list", ip);
					}
					tport_reset_packet_count_rate(tport); // Reset it to not add the iptables rule twice by mistake
				} else {
					LOGW("getnameinfo() failed: %s", gai_strerror(err));
				}
			}
		}
	}

	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) {

	};

  public:
	DoSProtection(Agent *ag) : Module(ag) {
		mIptablesVersionChecked = false;
		mIptablesSupportsWait = false;
		mThreadPool = new ThreadPool(1, 1000);
	}

	~DoSProtection() {
		delete mThreadPool;
	}
};

ModuleInfo<DoSProtection> DoSProtection::sInfo(
	"DoSProtection",
	"This module bans user when they are sending too much packets within a given timeframe. "
	"To see the list of currently banned IPs/ports, use iptables -L. ",
	{ "" },
	ModuleInfoBase::ModuleOid::DoSProtection
);
