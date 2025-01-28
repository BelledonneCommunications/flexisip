/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "cli.hh"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

#include <bctoolbox/ownership.hh>

#include <sofia-sip/su_log.h>

#include "flexisip/logmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "flexisip/utils/sip-uri.hh"

#include "agent.hh"
#include "cJSON.h"
#include "recordserializer.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/contact-key.hh"
#include "registrar/registrar-db.hh"
#include "sofia-sip/url.h"
#include "utils/string-utils.hh"

using namespace std;
using namespace sofiasip;
using namespace flexisip;

namespace {

constexpr const auto socket_send = send;
constexpr const auto socket_recv = recv;

void serializeRecord(SocketHandle& socket, Record* record) {
	string serialized;
	RecordSerializerJson().serialize(record, serialized, false);
	socket.send(serialized);
}

} // namespace

CommandLineInterface::CommandLineInterface(string name,
                                           const shared_ptr<ConfigManager>& cfg,
                                           const shared_ptr<SuRoot>& root)
    : mName(std::move(name)), handlers(make_shared<CliHandler::HandlerTable>()), mConfigManager(cfg), mRoot(root),
      mLogPrefix("CommandLineInterface[" + mName + "]") {
	if (pipe(mControlFds) == -1)
		throw FlexisipException{"cannot create control pipe of CommandLineInterface thread ("s + strerror(errno) + ")"};
}

CommandLineInterface::~CommandLineInterface() {
	if (mRunning) stop();
	close(mControlFds[0]);
	close(mControlFds[1]);
}

void CliHandler::unregister() {
	if (auto table = registration.lock()) {
		table->remove_if([this](const CliHandler& elem) { return &elem == this; });
	}
}

void CliHandler::registerTo(const shared_ptr<HandlerTable>& table) {
	unregister();
	table->emplace_front(*this);
	registration = table;
}

CliHandler::~CliHandler() {
	unregister();
}

future<void> CommandLineInterface::start() {
	mRunning = true;
	pthread_create(&mThread, nullptr, &CommandLineInterface::threadFunc, this);
	return mReady.get_future();
}

void CommandLineInterface::stop() {
	if (!mRunning) return;

	mRunning = false;
	if (write(mControlFds[1], "please stop", 1) == -1)
		throw FlexisipException{"cannot write to control pipe of CommandLineInterface thread ("s + strerror(errno) +
		                        ")"};

	pthread_join(mThread, nullptr);
}

void CommandLineInterface::parseAndAnswer(shared_ptr<SocketHandle> socket,
                                          const string& command,
                                          const vector<string>& args) {
	if ((command == "CONFIG_GET") || (command == "GET")) handleConfigGet(socket, args);
	else if ((command == "CONFIG_LIST") || (command == "LIST")) handleConfigList(socket, args);
	else if ((command == "CONFIG_SET") || (command == "SET")) handleConfigSet(socket, args);
	else dispatch(socket, command, args);
}

void CommandLineInterface::dispatch(const shared_ptr<SocketHandle>& socket,
                                    const string& command,
                                    const vector<string>& args) {
	auto output = string();
	for (CliHandler& handler : *handlers) {
		output = handler.handleCommand(command, args);
		if (!output.empty()) {
			break;
		}
	}
	if (output.empty()) {
		output = "Error - Unknown command: " + command;
	}
	socket->send(output);
}

void CommandLineInterface::registerHandler(CliHandler& handler) {
	handler.registerTo(handlers);
}

GenericEntry* CommandLineInterface::getGenericEntry(const string& arg) const {
	vector<string> arg_split = StringUtils::split(arg, "/");
	GenericStruct* root = mConfigManager->getRoot();

	if (arg == "all") return root;
	return find(root, arg_split);
}

void CommandLineInterface::handleConfigGet(const shared_ptr<SocketHandle>& socket, const vector<string>& args) {
	if (args.empty()) {
		socket->send("Error - 'CONFIG_GET' command expects 1 argument: <path>");
		return;
	}

	auto* entry = getGenericEntry(args.at(0));
	if (!entry) {
		socket->send("Error - Not found: " + args.at(0));
		return;
	}

	if (auto* gstruct = dynamic_cast<GenericStruct*>(entry)) socket->send(printSection(gstruct, false));
	else socket->send(printEntry(entry, false));
}

void CommandLineInterface::handleConfigList(const shared_ptr<SocketHandle>& socket, const vector<string>& args) {
	if (args.empty()) {
		socket->send("Error - 'CONFIG_LIST' command expects 1 argument: <section>");
		return;
	}

	GenericEntry* entry = getGenericEntry(args.at(0));
	if (!entry) {
		socket->send("Error - Not found: " + args.at(0));
		return;
	}

	if (auto* gstruct = dynamic_cast<GenericStruct*>(entry)) socket->send(printSection(gstruct, true));
	else socket->send(printEntry(entry, true));
}

void CommandLineInterface::handleConfigSet(const shared_ptr<SocketHandle>& socket, const vector<string>& args) {
	if (args.size() < 2) {
		socket->send("Error - 'CONFIG_SET' command expects 2 arguments: <path> <value>");
		return;
	}

	const auto& arg = args.at(0);
	auto* entry = getGenericEntry(arg);
	if (!entry) {
		socket->send("Error - Not found: " + args.at(0));
		return;
	}

	string value = args.at(1);
	auto* config_value = dynamic_cast<ConfigValue*>(entry);
	if (config_value && (arg == "global/debug")) {
		config_value->set(value);
		LogManager::get().setLogLevel(BCTBX_LOG_DEBUG);
		socket->send(arg + ": " + value);
	} else if (config_value && (arg == "global/log-level")) {
		config_value->set(value);
		LogManager::get().setLogLevel(LogManager::get().logLevelFromName(value));
		socket->send(arg + ": " + value);
	} else if (config_value && (arg == "global/syslog-level")) {
		config_value->set(value);
		LogManager::get().setSyslogLevel(LogManager::get().logLevelFromName(value));
		socket->send(arg + ": " + value);
	} else if (config_value && (arg == "global/sofia-level")) {
		try {
			const auto& valueInt = stoi(value);
			if (valueInt < 1 || valueInt > 9) {
				socket->send("Error - Failed to set Sofia-SIP log level: " + arg + " levels range from 1 to 9");
				return;
			}
			config_value->set(value);
			su_log_set_level(nullptr, valueInt);
			socket->send(arg + ": " + value);
		} catch (const exception& e) {
			socket->send("Error - Failed to set Sofia-SIP log level: "s + e.what());
		}
	} else if (config_value && (arg == "global/contextual-log-level")) {
		config_value->set(value);
		LogManager::get().setContextualLevel(LogManager::get().logLevelFromName(value));
		socket->send(arg + ": " + value);
	} else if (config_value && (arg == "global/contextual-log-filter")) {
		value = StringUtils::join(args, 1);
		config_value->set(value);
		LogManager::get().setContextualFilter(value);
		socket->send(arg + ": " + value);
	} else if (config_value && (arg == "global/show-body-for")) {
		try {
			value = StringUtils::join(args, 1);
			MsgSip::setShowBodyFor(value);
			config_value->set(value);
			socket->send(arg + ": " + value);
		} catch (const exception& e) {
			socket->send("Error - Failed to set " + arg + ": "s + e.what());
		}
	} else {
		socket->send("Error - Failed to set \"" + args.at(1) + "\": setting cannot be set while Flexisip is running");
	}
}

SocketHandle::SocketHandle(int handle) : mHandle(handle) {
}

SocketHandle::SocketHandle(SocketHandle&& other) : mHandle(other.mHandle) {
	other.mHandle = 0;
}

SocketHandle::~SocketHandle() {
	// On Linux, 0 is stdin. We can safely reserve that value as a flag.
	if (mHandle == 0) return;

	shutdown(mHandle, SHUT_RDWR);
	close(mHandle);
}

int SocketHandle::send(string_view message) const {
	return static_cast<int>(socket_send(mHandle, message.data(), message.length(), 0));
}

int SocketHandle::recv(char* buffer, size_t length, int flags) const {
	return static_cast<int>(socket_recv(mHandle, buffer, length, flags));
}

void CommandLineInterface::run() {
	int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_socket == -1) {
		LOGE << "Socket error " << errno << ": " << strerror(errno);
		stop();
	}

	const auto& pid = getpid();
	const auto& path = "/tmp/flexisip-" + mName + "-" + to_string(pid);
	LOGI << "CLI socket is at " << path;
	struct sockaddr_un local {};
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, path.c_str());
	unlink(local.sun_path);
	int local_length = static_cast<int>(strlen(local.sun_path) + sizeof(local.sun_family));
	if (::bind(server_socket, (struct sockaddr*)&local, local_length) == -1) {
		LOGE << "Bind error " << errno << ": " << strerror(errno);
		stop();
	}

	if (listen(server_socket, 1) == -1) {
		LOGE << "Listen error " << errno << ": " << strerror(errno);
		stop();
	}

	mReady.set_value();

	struct pollfd pfd[2];
	while (mRunning) {
		memset(pfd, 0, sizeof(pfd));
		pfd[0].fd = server_socket;
		pfd[0].events = POLLIN;
		pfd[1].fd = mControlFds[0];
		pfd[1].events = POLLIN;

		int ret = poll(pfd, 2, -1);
		if (ret == -1) {
			if (errno != EINTR) LOGE << "thread getting poll() error: " << strerror(errno);
			continue;
		} else if (ret == 0) {
			continue; // Timeout not possible
		} else if (pfd[0].revents != POLLIN) {
			continue; // When stopping from the control pipe, this is our chance to break out of the loop
		}
		// Otherwise we have something to accept on our server_socket

		struct sockaddr_un remote {};
		auto remote_length = (socklen_t)sizeof(remote);
		const auto& child_handle = accept(server_socket, (struct sockaddr*)&remote, &remote_length);
		if (child_handle == -1) {
			LOGE << "Accept error " << errno << ": " << strerror(errno);
			continue;
		}

		auto child_socket = make_shared<SocketHandle>(child_handle);

		bool finished = false;
		do {
			char buffer[512] = {0};
			const auto& n = child_socket->recv(buffer, sizeof(buffer) - 1, 0);
			if (n < 0) {
				LOGE << "Recv error " << errno << ": " << strerror(errno);
				finished = true;
			} else if (n > 0) {
				LOGI << "Received: " << buffer;
				auto split_query = StringUtils::split(string(buffer), " ");
				auto command = split_query.front();
				split_query.erase(split_query.begin());
				mRoot->addToMainLoop([this, weakGuard = weak_ptr{validThisGuard}, childSocket = std::move(child_socket),
				                      cmd = std::move(command), splitQuery = std::move(split_query)]() mutable {
					if (!weakGuard.lock() /* means that "this" is deleted */) return;

					try {
						parseAndAnswer(std::move(childSocket), cmd, splitQuery);
					} catch (const exception& exception) {
						LOGE_CTX(mLogPrefix, "run") << "Caught an unexpected exception while executing command (" << cmd
						                            << "): " << exception.what();
					}
				});
				finished = true;
			}
		} while (!finished && mRunning);
	}

	shutdown(server_socket, SHUT_RDWR);
	close(server_socket);
	unlink(path.c_str());
}

GenericEntry* CommandLineInterface::find(GenericStruct* root, vector<string>& path) {
	auto elem = path.front();
	path.erase(path.begin());
	for (const auto& entry : root->getChildren()) {
		if (!entry || (entry->getName() != elem)) continue;

		if (path.empty()) {
			return entry.get();
		} else {
			auto gstruct = dynamic_cast<GenericStruct*>(entry.get());
			if (gstruct) return find(gstruct, path);
			return nullptr;
		}
	}
	return nullptr;
}

string CommandLineInterface::printEntry(GenericEntry* entry, bool printHelpInsteadOfValue) {
	const auto* gstruct = dynamic_cast<GenericStruct*>(entry);
	bool isNode = (gstruct != nullptr);
	string answer;

	if (printHelpInsteadOfValue) {
		if (isNode) answer += "[";
		answer += entry->getName();
		if (isNode) answer += "]";
		answer += ": " + entry->getHelp();
	} else {
		if (isNode) {
			answer += "[" + gstruct->getCompleteName() + "]";
		} else {
			auto* counter = dynamic_cast<StatCounter64*>(entry);
			if (counter) {
				answer += counter->getCompleteName() + ": " + to_string(counter->read());
			} else {
				const auto* value = dynamic_cast<ConfigValue*>(entry);
				if (value) answer += value->getCompleteName() + ": " + value->get();
			}
		}
	}
	return answer;
}

string CommandLineInterface::printSection(GenericStruct* gstruct, bool printHelpInsteadOfValue) {
	string answer{};
	for (const auto& child : gstruct->getChildren()) {
		if (child) answer += printEntry(child.get(), printHelpInsteadOfValue) + "\r\n";
	}
	return answer;
}

void* CommandLineInterface::threadFunc(void* arg) {
	auto* thiz = reinterpret_cast<CommandLineInterface*>(arg);
	thiz->run();
	return nullptr;
}

ProxyCommandLineInterface::ProxyCommandLineInterface(const shared_ptr<ConfigManager>& cfg,
                                                     const shared_ptr<Agent>& agent)
    : CommandLineInterface("proxy", cfg, agent->getRoot()), mAgent(agent) {
}

class CommandListener : public ContactUpdateListener {
public:
	explicit CommandListener(shared_ptr<SocketHandle> socket) : mSocket(std::move(socket)) {
	}

	void onError(const SipStatus&) override {
		mSocket->send("Error - Failed to connect to the registrar database");
	}

	void onInvalid(const SipStatus&) override {
		mSocket->send("Error - Invalid record");
	}

	void onContactUpdated(const shared_ptr<ExtendedContact>&) override {
	}

protected:
	shared_ptr<SocketHandle> mSocket;
};

class SerializeRecordWhenFound : public CommandListener {
public:
	using CommandListener::CommandListener;

	void onRecordFound(const shared_ptr<Record>& r) override {
		if (!r || r->isEmpty()) {
			// The Redis implementation returns an empty record instead of nullptr, see anchor WKADREGMIGDELREC
			mSocket->send("Error - 404 Not Found: the registrar database does not contain the requested AOR");
			return;
		}

		serializeRecord(*mSocket, r.get());
	}
};

void ProxyCommandLineInterface::handleRegistrarGet(shared_ptr<SocketHandle> socket, const vector<string>& args) {
	if (args.empty()) {
		socket->send("Error - 'REGISTRAR_GET' command expects 1 argument: <aor>");
		return;
	}

	SipUri aor;
	try {
		aor = SipUri(args.at(0));
	} catch (const InvalidUrlError&) {
		socket->send("Error - "s + args.at(0));
		return;
	}

	auto listener = make_shared<SerializeRecordWhenFound>(std::move(socket));
	mAgent->getRegistrarDb().fetch(aor, listener, false);
}

void ProxyCommandLineInterface::handleRegistrarUpsert(shared_ptr<SocketHandle> socket, const vector<string>& args) {
	if (args.size() < 3 or 4 < args.size()) {
		socket->send("Error - 'REGISTRAR_UPSERT' command expects 3 to 4 arguments: <aor> <uri> <expire> [<uuid>]");
		return;
	}

	SipUri aor;
	try {
		aor = SipUri(args.at(0));
	} catch (const InvalidUrlError&) {
		socket->send("Error - Invalid SIP URI: "s + args.at(0));
		return;
	}

	string sipInstance(";+sip.instance=");
	try {
		sipInstance += args.at(3);
	} catch (const out_of_range& _) {
		// Generate a unique (enough) ID that will *not* be considered as a placeholder
		sipInstance += "fs-cli-gen-" + ContactKey::generateUniqueId();
	}

	Home home{};
	auto* contact = sip_contact_make(home.home(), (args.at(1) + sipInstance).c_str());
	if (!contact) {
		// Very unlikely, sip_contact_make accepts almost anything
		socket->send("Error - Failed to create SIP contact header: "s + args.at(1));
		return;
	}
	try {
		SipUri(contact->m_url);
	} catch (const InvalidUrlError&) {
		socket->send("Error - Invalid SIP URI: "s + args.at(1));
		return;
	}

	int expire;
	{
		stringstream ss{};
		ss << args.at(2);
		ss >> expire;
	}
	if (expire <= 0) {
		socket->send("Error -  Expire parameter is not strictly positive, use 'REGISTRAR_DELETE' if you want to remove "
		             "a binding");
		return;
	}

	BindingParameters params{};
	params.globalExpire = expire;
	params.callId = "fs-cli-upsert";
	mAgent->getRegistrarDb().bind(aor, contact, params, make_shared<SerializeRecordWhenFound>(std::move(socket)));
}

class SerializeRecordEvenIfEmpty : public CommandListener {
public:
	using CommandListener::CommandListener;

	void onRecordFound(const shared_ptr<Record>& r) override {
		if (r == nullptr) { // Unreachable (2024-03-05)
			mSocket->send("Error - 404 Not Found: the registrar database does not contain the requested AOR");
			return;
		}

		serializeRecord(*mSocket, r.get());
	}
};

void ProxyCommandLineInterface::handleRegistrarDelete(shared_ptr<SocketHandle> socket, const vector<string>& args) {
	if (args.size() < 2) {
		socket->send("Error - 'REGISTRAR_DELETE' command expects 2 arguments: <uri> <uuid>.");
		return;
	}

	SipUri recordKey;
	try {
		recordKey = SipUri(args.at(0));
	} catch (const InvalidUrlError&) {
		socket->send("Error - Invalid SIP URI: " + args.at(0));
		return;
	}
	const auto& contactKey = args.at(1);

	BindingParameters parameter;
	parameter.globalExpire = 0; // un-REGISTER <=> delete
	parameter.callId = "fs-cli-delete";

	// Force binding logic to match the target contact based on this key (even if it is an auto-generated placeholder).
	// I.e. prevent matching on RFC 3261's URI matching rules
	string sipInstance{"+sip.instance=" + contactKey};
	if (string_utils::startsWith(contactKey, ContactKey::kAutoGenTag)) sipInstance += ContactKey::kNotAPlaceholderFlag;
	SipHeaderContact contact{recordKey, sipInstance.data()};

	mAgent->getRegistrarDb().bind(recordKey, reinterpret_cast<const sip_contact_t*>(contact.getNativePtr()), parameter,
	                              make_shared<SerializeRecordEvenIfEmpty>(std::move(socket)));
}

void ProxyCommandLineInterface::handleRegistrarClear(shared_ptr<SocketHandle> socket, const vector<string>& args) {
	if (args.empty()) {
		socket->send("Error - 'REGISTRAR_CLEAR' command expects 1 argument: <aor>");
		return;
	}

	class ClearListener : public CommandListener {
	public:
		ClearListener(shared_ptr<SocketHandle> socket, Record::Key&& uri, RegistrarDb& registrarDb)
		    : CommandListener(std::move(socket)), mUri(std::move(uri)), mRegistrarDb(registrarDb) {
		}

		void onRecordFound(const shared_ptr<Record>& r) override {
			mRegistrarDb.publish(r->getKey(), "");
			mSocket->send("Done - Cleared AOR: " + mUri.asString());
		}

		void onError(const SipStatus&) override {
			mSocket->send("Error - Failed to clear AOR: " + mUri.asString());
		}

		void onInvalid(const SipStatus&) override {
			mSocket->send("Error - Failed to clear, invalid AOR: " + mUri.asString());
		}

	private:
		Record::Key mUri;
		RegistrarDb& mRegistrarDb;
	};

	SipUri aor;
	try {
		aor = SipUri(args.at(0));
	} catch (const InvalidUrlError&) {
		socket->send("Error - Invalid SIP URI: " + args.at(0));
		return;
	}

	auto msg = MsgSip(ownership::owned(nta_msg_create(mAgent->getSofiaAgent(), 0)));
	auto* sip = msg.getSip();
	sip->sip_from = sip_from_create(msg.getHome(), reinterpret_cast<const url_string_t*>(aor.get()));
	mAgent->getRegistrarDb().clear(
	    msg, make_shared<ClearListener>(std::move(socket), Record::Key(aor, mAgent->getRegistrarDb().useGlobalDomain()),
	                                    mAgent->getRegistrarDb()));
}

void ProxyCommandLineInterface::handleRegistrarDump(const shared_ptr<SocketHandle>& socket, const vector<string>&) {
	list<string> aorList;

	mAgent->getRegistrarDb().getLocalRegisteredAors(aorList);

	cJSON* root = cJSON_CreateObject();
	cJSON* contacts = cJSON_CreateArray();

	cJSON_AddItemToObject(root, "aors", contacts);
	for (const auto& aor : aorList) {
		cJSON* pitem = cJSON_CreateString(aor.c_str());
		cJSON_AddItemToArray(contacts, pitem);
	}
	auto* jsonOutput = cJSON_Print(root);
	socket->send(jsonOutput);
	free(jsonOutput);
	cJSON_Delete(root);
}

void ProxyCommandLineInterface::parseAndAnswer(shared_ptr<SocketHandle> socket,
                                               const string& command,
                                               const vector<string>& args) {
	if (command == "REGISTRAR_CLEAR") {
		handleRegistrarClear(std::move(socket), args);
	} else if (command == "REGISTRAR_GET") {
		handleRegistrarGet(std::move(socket), args);
	} else if (command == "REGISTRAR_UPSERT") {
		handleRegistrarUpsert(std::move(socket), args);
	} else if (command == "REGISTRAR_DELETE") {
		handleRegistrarDelete(std::move(socket), args);
	} else if (command == "REGISTRAR_DUMP") {
		handleRegistrarDump(socket, args);
	} else {
		CommandLineInterface::parseAndAnswer(std::move(socket), command, args);
	}
}