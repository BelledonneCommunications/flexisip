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

#include "cli.hh"

#include <cerrno>
#include <cstring>

#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bctoolbox/ownership.hh>

#include "flexisip/logmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "flexisip/utils/sip-uri.hh"

#include "agent.hh"
#include "cJSON.h"
#include "eventlogs/writers/event-log-writer.hh"
#include "recordserializer.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/contact-key.hh"
#include "registrar/registrar-db.hh"
#include "sofia-sip/url.h"
#include "utils/string-utils.hh"

using namespace flexisip;
using namespace std;

namespace {

constexpr const auto socket_send = send;
constexpr const auto socket_recv = recv;

void serializeRecord(SocketHandle& socket, Record* record) {
	std::string serialized;
	RecordSerializerJson().serialize(record, serialized, false);
	socket.send(serialized);
}

} // namespace

CommandLineInterface::CommandLineInterface(const std::string& name, const std::shared_ptr<ConfigManager>& cfg)
    : mName(name), handlers(std::make_shared<CliHandler::HandlerTable>()), mConfigManager(cfg) {
	if (pipe(mControlFds) == -1) LOGF("Cannot create control pipe of CommandLineInterface thread: %s", strerror(errno));
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

void CliHandler::registerTo(const std::shared_ptr<HandlerTable>& table) {
	unregister();
	table->push_front(*this);
	registration = table;
}

CliHandler::~CliHandler() {
	unregister();
}

std::future<void> CommandLineInterface::start() {
	mRunning = true;
	pthread_create(&mThread, nullptr, &CommandLineInterface::threadfunc, this);
	return mReady.get_future();
}

void CommandLineInterface::stop() {
	if (!mRunning) return;

	mRunning = false;
	if (write(mControlFds[1], "please stop", 1) == -1)
		LOGF("Cannot write to control pipe of CommandLineInterface thread: %s", strerror(errno));
	pthread_join(mThread, nullptr);
}

void CommandLineInterface::parseAndAnswer(SocketHandle&& socket,
                                          const std::string& command,
                                          const std::vector<std::string>& args) {
	if ((command == "CONFIG_GET") || (command == "GET")) handleConfigGet(std::move(socket), args);
	else if ((command == "CONFIG_LIST") || (command == "LIST")) handleConfigList(std::move(socket), args);
	else if ((command == "CONFIG_SET") || (command == "SET")) handleConfigSet(std::move(socket), args);
	else dispatch(std::move(socket), command, args);
}

void CommandLineInterface::dispatch(SocketHandle&& socket,
                                    const std::string& command,
                                    const std::vector<std::string>& args) {
	auto output = std::string();
	for (CliHandler& handler : *handlers) {
		output = handler.handleCommand(command, args);
		if (!output.empty()) {
			break;
		}
	}
	if (output.empty()) {
		output = "Error: unknown command " + command;
	}
	socket.send(output);
}

void CommandLineInterface::registerHandler(CliHandler& handler) {
	handler.registerTo(handlers);
}

GenericEntry* CommandLineInterface::getGenericEntry(const std::string& arg) const {
	std::vector<std::string> arg_split = StringUtils::split(arg, "/");
	GenericStruct* root = mConfigManager->getRoot();

	if (arg == "all") return root;
	return find(root, arg_split);
}

void CommandLineInterface::handleConfigGet(SocketHandle&& socket, const std::vector<std::string>& args) {
	if (args.size() < 1) {
		socket.send("Error: at least 1 argument is expected for the CONFIG_GET command");
		return;
	}

	GenericEntry* entry = getGenericEntry(args.front());
	if (!entry) {
		socket.send("Error: " + args.front() + " not found");
		return;
	}

	GenericStruct* gstruct = dynamic_cast<GenericStruct*>(entry);
	if (gstruct) socket.send(printSection(gstruct, false));
	else socket.send(printEntry(entry, false));
}

void CommandLineInterface::handleConfigList(SocketHandle&& socket, const std::vector<std::string>& args) {
	if (args.size() < 1) {
		socket.send("Error: at least 1 argument is expected for the CONFIG_LIST command");
		return;
	}

	GenericEntry* entry = getGenericEntry(args.front());
	if (!entry) {
		socket.send("Error: " + args.front() + " not found");
		return;
	}

	GenericStruct* gstruct = dynamic_cast<GenericStruct*>(entry);
	if (gstruct) socket.send(printSection(gstruct, true));
	else socket.send(printEntry(entry, true));
}

void CommandLineInterface::handleConfigSet(SocketHandle&& socket, const std::vector<std::string>& args) {
	if (args.size() < 2) {
		socket.send("Error: at least 2 arguments are expected for the CONFIG_SET command");
		return;
	}

	std::string arg = args.front();
	GenericEntry* entry = getGenericEntry(arg);
	if (!entry) {
		socket.send("Error: " + args.front() + " not found");
		return;
	}

	std::string value = args.at(1);
	auto* config_value = dynamic_cast<ConfigValue*>(entry);
	if (config_value && (arg == "global/debug")) {
		config_value->set(value);
		LogManager::get().setLogLevel(BCTBX_LOG_DEBUG);
		socket.send("debug : " + value);
	} else if (config_value && (arg == "global/log-level")) {
		config_value->set(value);
		LogManager::get().setLogLevel(LogManager::get().logLevelFromName(value));
		socket.send("log-level : " + value);
	} else if (config_value && (arg == "global/syslog-level")) {
		config_value->set(value);
		LogManager::get().setSyslogLevel(LogManager::get().logLevelFromName(value));
		socket.send("syslog-level : " + value);
	} else if (config_value && (arg == "global/contextual-log-level")) {
		config_value->set(value);
		LogManager::get().setContextualLevel(LogManager::get().logLevelFromName(value));
		socket.send("contextual-log-level : " + value);
	} else if (config_value && (arg == "global/contextual-log-filter")) {
		value = StringUtils::join(args, 1);
		config_value->set(value);
		LogManager::get().setContextualFilter(value);
		socket.send("contextual-log-filter : " + value);
	} else if (config_value && (arg == "global/show-body-for")) {
		try {
			value = StringUtils::join(args, 1);
			MsgSip::setShowBodyFor(value);
			config_value->set(value);
			socket.send("show-body-for : " + value);
		} catch (const exception& e) {
			socket.send("show-body-for : not modified, errors in args. "s + e.what());
		}
	} else {
		socket.send("Only debug, log-level and syslog-level from global can be updated while flexisip is running");
	}
}

SocketHandle::SocketHandle(int handle) : mHandle(handle) {
}
SocketHandle::SocketHandle(SocketHandle&& other) : mHandle(other.mHandle) {
	other.mHandle = 0;
}
SocketHandle::~SocketHandle() {
	// On Linux, 0 is stdin. We can safely reserve that value as a flag
	if (mHandle == 0) return;

	shutdown(mHandle, SHUT_RDWR);
	close(mHandle);
}
int SocketHandle::send(string_view message) {
	return socket_send(mHandle, message.data(), message.length(), 0);
}
int SocketHandle::recv(char* buffer, size_t length, int flags) {
	return socket_recv(mHandle, buffer, length, flags);
}

void CommandLineInterface::run() {
	int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_socket == -1) {
		SLOGE << "Socket error " << errno << ": " << std::strerror(errno);
		stop();
	}

	int pid = getpid();
	std::string path = "/tmp/flexisip-" + mName + "-" + std::to_string(pid);
	SLOGD << "CLI socket is at " << path;
	struct sockaddr_un local;
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, path.c_str());
	unlink(local.sun_path);
	int local_length = strlen(local.sun_path) + sizeof(local.sun_family);
	if (::bind(server_socket, (struct sockaddr*)&local, local_length) == -1) {
		SLOGE << "Bind error " << errno << ": " << std::strerror(errno);
		stop();
	}

	if (listen(server_socket, 1) == -1) {
		SLOGE << "Listen error " << errno << ": " << std::strerror(errno);
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
			if (errno != EINTR) SLOGE << "CommandLineInterface thread getting poll() error: " << strerror(errno);
			continue;
		} else if (ret == 0) {
			continue; // Timeout not possible
		} else if (pfd[0].revents != POLLIN) {
			continue; // When stopping from the control pipe, this is our chance to break out of the loop
		}
		// Otherwise we have something to accept on our server_socket

		struct sockaddr_un remote;
		auto remote_length = (socklen_t)sizeof(remote);
		int child_handle = accept(server_socket, (struct sockaddr*)&remote, &remote_length);
		if (child_handle == -1) {
			SLOGE << "Accept error " << errno << ": " << std::strerror(errno);
			continue;
		}
		SocketHandle child_socket(child_handle);

		bool finished = false;
		do {
			char buffer[512] = {0};
			int n = child_socket.recv(buffer, sizeof(buffer) - 1, 0);
			if (n < 0) {
				SLOGE << "Recv error " << errno << ": " << std::strerror(errno);
				finished = true;
			} else if (n > 0) {
				SLOGD << "CommandLineInterface " << mName << " received: " << buffer;
				auto split_query = StringUtils::split(buffer, " ");
				std::string command = split_query.front();
				split_query.erase(split_query.begin());
				parseAndAnswer(std::move(child_socket), command, split_query);
				finished = true;
			}
		} while (!finished && mRunning);
	}

	shutdown(server_socket, SHUT_RDWR);
	close(server_socket);
	unlink(path.c_str());
}

GenericEntry* CommandLineInterface::find(GenericStruct* root, std::vector<std::string>& path) {
	std::string elem = path.front();
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

std::string CommandLineInterface::printEntry(GenericEntry* entry, bool printHelpInsteadOfValue) {
	auto gstruct = dynamic_cast<GenericStruct*>(entry);
	bool isNode = (gstruct != nullptr);
	std::string answer;

	if (printHelpInsteadOfValue) {
		if (isNode) answer += "[";
		answer += entry->getName();
		if (isNode) answer += "]";
		answer += " : " + entry->getHelp();
	} else {
		if (isNode) {
			answer += "[" + gstruct->getName() + "]";
		} else {
			auto counter = dynamic_cast<StatCounter64*>(entry);
			if (counter) {
				answer += counter->getName() + " : " + std::to_string(counter->read());
			} else {
				auto value = dynamic_cast<ConfigValue*>(entry);
				if (value) answer += value->getName() + " : " + value->get();
			}
		}
	}
	return answer;
}

std::string CommandLineInterface::printSection(GenericStruct* gstruct, bool printHelpInsteadOfValue) {
	std::string answer = "";
	for (const auto& child : gstruct->getChildren()) {
		if (child) answer += printEntry(child.get(), printHelpInsteadOfValue) + "\r\n";
	}
	return answer;
}

void* CommandLineInterface::threadfunc(void* arg) {
	CommandLineInterface* thiz = reinterpret_cast<CommandLineInterface*>(arg);
	thiz->run();
	return nullptr;
}

ProxyCommandLineInterface::ProxyCommandLineInterface(const std::shared_ptr<ConfigManager>& cfg,
                                                     const std::shared_ptr<Agent>& agent)
    : CommandLineInterface("proxy", cfg), mAgent(agent) {
}

class CommandListener : public ContactUpdateListener {
public:
	CommandListener(SocketHandle&& socket) : mSocket(std::move(socket)) {
	}

	void onError(const SipStatus&) override {
		mSocket.send("Error connecting to the Registrar");
	}
	void onInvalid(const SipStatus&) override {
		mSocket.send("Error: Invalid Record");
	}
	// Mandatory since we inherit from ContactUpdateListener
	void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
	}

protected:
	SocketHandle mSocket;
};

class SerializeRecordWhenFound : public CommandListener {
public:
	using CommandListener::CommandListener;

	void onRecordFound(const shared_ptr<Record>& r) override {
		if (!r || r->isEmpty()) {
			// The Redis implementation returns an empty record instead of nullptr, see anchor WKADREGMIGDELREC
			mSocket.send("Error 404: Not Found. The Registrar does not contain the requested AOR.");
			return;
		}

		serializeRecord(mSocket, r.get());
	}
};

void ProxyCommandLineInterface::handleRegistrarGet(SocketHandle&& socket, const std::vector<std::string>& args) {
	if (args.size() < 1) {
		socket.send("Error: a SIP address argument is expected for the REGISTRAR_GET command");
		return;
	}

	SipUri url;
	try {
		url = SipUri(args.front().c_str());
	} catch (const sofiasip::InvalidUrlError& e) {
		socket.send(string{"Error: invalid SIP address ["} + e.what() + "]");
		return;
	}

	auto listener = make_shared<SerializeRecordWhenFound>(std::move(socket));
	mAgent->getRegistrarDb().fetch(url, listener, false);
}

void ProxyCommandLineInterface::handleRegistrarUpsert(SocketHandle&& socket, const std::vector<std::string>& args) {
	if (args.size() < 3) {
		socket.send("Error: REGISTRAR_UPSERT expects at least 3 arguments: <aor> <contact_address> <expire>. " +
		            std::to_string(args.size()) + " were provided.");
		return;
	}
	if (4 < args.size()) {
		socket.send(
		    "Error: REGISTRAR_UPSERT expects at most 4 arguments: <aor> <contact_address> <expire> <unique-id>. " +
		    std::to_string(args.size()) + " were provided.");
		return;
	}

	SipUri aor;
	try {
		aor = SipUri(args.at(0));
	} catch (const sofiasip::InvalidUrlError& e) {
		socket.send("Error: aor parameter is not a valid SIP address ["s + e.what() + "]");
		return;
	}

	std::string instance_id(";+sip.instance=");
	try {
		instance_id += args.at(3);
	} catch (const std::out_of_range& _) {
		// Generate a unique (enough) ID that will *not* be considered as a placeholder
		instance_id += "fs-cli-gen-" + ContactKey::generateUniqueId();
	}

	sofiasip::Home home{};
	auto* contact = sip_contact_make(home.home(), (args.at(1) + instance_id).c_str());
	if (!contact) {
		// Very unlikely, sip_contact_make accepts almost anything
		socket.send("Error: contact_address parameter is not a valid SIP contact ["s + args.at(1) + "]");
		return;
	}
	try {
		SipUri(contact->m_url);
	} catch (const sofiasip::InvalidUrlError& e) {
		socket.send("Error: contact_address parameter does not contain a valid SIP address ["s + e.what() + "] in [" +
		            args.at(1) + "]");
		return;
	}

	int expire;
	{
		std::stringstream ss{};
		ss << args.at(2);
		ss >> expire;
	}
	if (expire <= 0) {
		socket.send(
		    "Error: expire parameter is not strictly positive. Use REGISTRAR_DELETE if you want to remove a binding.");
		return;
	}

	BindingParameters params{};
	params.globalExpire = expire;
	params.callId = "fs-cli-upsert";
	mAgent->getRegistrarDb().bind(aor, contact, params, std::make_shared<SerializeRecordWhenFound>(std::move(socket)));
}

class SerializeRecordEvenIfEmpty : public CommandListener {
public:
	using CommandListener::CommandListener;

	void onRecordFound(const shared_ptr<Record>& r) override {
		if (r == nullptr) { // Unreachable (2024-03-05)
			mSocket.send("Error 404: Not Found. The Registrar does not contain the requested AOR.");
			return;
		}

		serializeRecord(mSocket, r.get());
	}
};

void ProxyCommandLineInterface::handleRegistrarDelete(SocketHandle&& socket, const std::vector<std::string>& args) {
	if (args.size() < 2) {
		socket.send("Error: an URI arguments is expected for the REGISTRAR_DELETE command");
		return;
	}

	const auto& recordKey = SipUri(args.at(0));
	const auto& contactKey = args.at(1);

	auto home = sofiasip::Home();
	BindingParameters parameter;
	parameter.globalExpire = 0; // un-REGISTER <=> delete
	parameter.callId = "fs-cli-delete";

	// Force binding logic to match the target contact based on this key (even if it is an auto-generated placeholder).
	// I.e. prevent matching on RFC 3261's URI matching rules
	const auto& sipInstance = "+sip.instance=" + contactKey + ContactKey::kNotAPlaceholderFlag;
	const auto* const stubContact = sip_contact_create(
	    home.home(), reinterpret_cast<const url_string_t*>(recordKey.get()), sipInstance.c_str(), nullptr);

	mAgent->getRegistrarDb().bind(recordKey, stubContact, parameter,
	                              std::make_shared<SerializeRecordEvenIfEmpty>(std::move(socket)));
}

void ProxyCommandLineInterface::handleRegistrarClear(SocketHandle&& socket, const std::vector<std::string>& args) {
	if (args.size() < 1) {
		socket.send("Error: a SIP address argument is expected for the REGISTRAR_CLEAR command");
		return;
	}

	class ClearListener : public CommandListener {
	public:
		ClearListener(SocketHandle&& socket, Record::Key&& uri, RegistrarDb& registrarDb)
		    : CommandListener(std::move(socket)), mUri(std::move(uri)), mRegistrarDb(registrarDb) {
		}

		void onRecordFound(const shared_ptr<Record>& r) override {
			mRegistrarDb.publish(r->getKey(), "");
			mSocket.send("Done: cleared record " + static_cast<const string&>(mUri));
		}
		void onError(const SipStatus&) override {
			mSocket.send("Error: cannot clear record " + static_cast<const string&>(mUri));
		}
		void onInvalid(const SipStatus&) override {
			mSocket.send("Error: cannot clear record " + static_cast<const string&>(mUri));
		}

	private:
		Record::Key mUri;
		RegistrarDb& mRegistrarDb;
	};

	SipUri url;
	try {
		url = SipUri(args.front().c_str());
	} catch (const sofiasip::InvalidUrlError& e) {
		socket.send(string{"Error: invalid SIP address ["} + e.what() + "]");
		return;
	}

	auto msg = MsgSip(ownership::owned(nta_msg_create(mAgent->getSofiaAgent(), 0)));
	auto* sip = msg.getSip();
	sip->sip_from = sip_from_create(msg.getHome(), reinterpret_cast<const url_string_t*>(url.get()));
	mAgent->getRegistrarDb().clear(
	    msg,
	    std::make_shared<ClearListener>(std::move(socket), Record::Key(url, mAgent->getRegistrarDb().useGlobalDomain()),
	                                    mAgent->getRegistrarDb()));
}

void ProxyCommandLineInterface::handleRegistrarDump(SocketHandle&& socket,
                                                    [[maybe_unused]] const std::vector<std::string>& args) {
	list<string> aorList;

	mAgent->getRegistrarDb().getLocalRegisteredAors(aorList);

	cJSON* root = cJSON_CreateObject();
	cJSON* contacts = cJSON_CreateArray();

	cJSON_AddItemToObject(root, "aors", contacts);
	for (auto& aor : aorList) {
		cJSON* pitem = cJSON_CreateString(aor.c_str());
		cJSON_AddItemToArray(contacts, pitem);
	}
	char* jsonOutput = cJSON_Print(root);
	socket.send(jsonOutput);
	free(jsonOutput);
	cJSON_Delete(root);
}

void ProxyCommandLineInterface::parseAndAnswer(SocketHandle&& socket,
                                               const std::string& command,
                                               const std::vector<std::string>& args) {
	if (command == "REGISTRAR_CLEAR") {
		handleRegistrarClear(std::move(socket), args);
	} else if (command == "REGISTRAR_GET") {
		handleRegistrarGet(std::move(socket), args);
	} else if (command == "REGISTRAR_UPSERT") {
		handleRegistrarUpsert(std::move(socket), args);
	} else if (command == "REGISTRAR_DELETE") {
		handleRegistrarDelete(std::move(socket), args);
	} else if (command == "REGISTRAR_DUMP") {
		handleRegistrarDump(std::move(socket), args);
	} else {
		CommandLineInterface::parseAndAnswer(std::move(socket), command, args);
	}
}
