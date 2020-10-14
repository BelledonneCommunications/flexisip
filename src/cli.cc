/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2016  Belledonne Communications SARL, All rights reserved.

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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <poll.h>

#include "cli.hh"
#include <flexisip/common.hh>
#include <flexisip/logmanager.hh>
#include <flexisip/registrardb.hh>

using namespace flexisip;
using namespace std;

CommandLineInterface::CommandLineInterface(const std::string &name) : mName(name) {
	if (pipe(mControlFds) == -1)
		LOGF("Cannot create control pipe of CommandLineInterface thread: %s", strerror(errno));
}

CommandLineInterface::~CommandLineInterface() {
	if (mRunning)
		stop();
	close(mControlFds[0]);
	close(mControlFds[1]);
}


void CommandLineInterface::start() {
	mRunning = true;
	pthread_create(&mThread, nullptr, &CommandLineInterface::threadfunc, this);
}

void CommandLineInterface::stop() {
	if (!mRunning)
		return;

	mRunning = false;
	if (write(mControlFds[1], "please stop", 1) == -1)
		LOGF("Cannot write to control pipe of CommandLineInterface thread: %s", strerror(errno));
	pthread_join(mThread, nullptr);
}

void CommandLineInterface::answer(unsigned int socket, const std::string &message) {
	send(socket, message.c_str(), message.length(), 0);
	shutdown(socket, SHUT_RDWR);
	close(socket);
}

void CommandLineInterface::parseAndAnswer(unsigned int socket, const std::string &command, const std::vector<std::string> &args) {
	if ((command == "CONFIG_GET") || (command == "GET"))
		handle_config_get_command(socket, args);
	else if ((command == "CONFIG_LIST") || (command == "LIST"))
		handle_config_list_command(socket, args);
	else if ((command == "CONFIG_SET") || (command == "SET"))
		handle_config_set_command(socket, args);
	else
		answer(socket, "Error: unknown command " + command);
}

GenericEntry *CommandLineInterface::get_generic_entry(const std::string &arg) const {
	std::vector<std::string> arg_split = split(arg, '/');
	GenericManager *manager = GenericManager::get();
	GenericStruct *root = manager->getRoot();

	if (arg == "all")
		return root;
	return find(root, arg_split);
}

void CommandLineInterface::handle_config_get_command(unsigned int socket, const std::vector<std::string> &args) {
	if (args.size() < 1) {
		answer(socket, "Error: at least 1 argument is expected for the CONFIG_GET command");
		return;
	}

	GenericEntry *entry = get_generic_entry(args.front());
	if (!entry) {
		answer(socket, "Error: " + args.front() + " not found");
		return;
	}

	GenericStruct *gstruct = dynamic_cast<GenericStruct *>(entry);
	if (gstruct)
		answer(socket, printSection(gstruct, false));
	else
		answer(socket, printEntry(entry, false));
}

void CommandLineInterface::handle_config_list_command(unsigned int socket, const std::vector<std::string> &args) {
	if (args.size() < 1) {
		answer(socket, "Error: at least 1 argument is expected for the CONFIG_LIST command");
		return;
	}

	GenericEntry *entry = get_generic_entry(args.front());
	if (!entry) {
		answer(socket, "Error: " + args.front() + " not found");
		return;
	}

	GenericStruct *gstruct = dynamic_cast<GenericStruct *>(entry);
	if (gstruct)
		answer(socket, printSection(gstruct, true));
	else
		answer(socket, printEntry(entry, true));
}

string CommandLineInterface::agregate(const std::vector<std::string> &args, size_t from_pos){
	ostringstream ostr;
	for (size_t i = from_pos; i < args.size(); ++i){
		ostr << args[i] << " ";
	}
	return ostr.str();
}

void CommandLineInterface::handle_config_set_command(unsigned int socket, const std::vector<std::string> &args) {
	if (args.size() < 2) {
		answer(socket, "Error: at least 2 arguments are expected for the CONFIG_SET command");
		return;
	}

	std::string arg = args.front();
	GenericEntry *entry = get_generic_entry(arg);
	if (!entry) {
		answer(socket, "Error: " + args.front() + " not found");
		return;
	}

	std::string value = args.at(1);
	ConfigValue *config_value = dynamic_cast<ConfigValue *>(entry);
	if (config_value && (arg == "global/debug")) {
		config_value->set(value);
		LogManager::get().setLogLevel(BCTBX_LOG_DEBUG);
		answer(socket, "debug : " + value);
	} else if (config_value && (arg == "global/log-level")) {
		config_value->set(value);
		LogManager::get().setLogLevel(LogManager::get().logLevelFromName(value));
		answer(socket, "log-level : " + value);
	} else if (config_value && (arg == "global/syslog-level")) {
		config_value->set(value);
		LogManager::get().setSyslogLevel(LogManager::get().logLevelFromName(value));
		answer(socket, "syslog-level : " + value);
	} else if (config_value && (arg == "global/contextual-log-level")) {
		config_value->set(value);
		LogManager::get().setContextualLevel(LogManager::get().logLevelFromName(value));
		answer(socket, "contextual-log-level : " + value);
	}else if (config_value && (arg == "global/contextual-log-filter")) {
		value = agregate(args, 1);
		config_value->set(value);
		LogManager::get().setContextualFilter(value);
		answer(socket, "contextual-log-filter : " + value);
	} else {
		answer(socket, "Only debug, log-level and syslog-level from global can be updated while flexisip is running");
	}
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
	if (::bind(server_socket, (struct sockaddr *)&local, local_length) == -1) {
		SLOGE << "Bind error " << errno << ": " << std::strerror(errno);
		stop();
	}

	if (listen(server_socket, 1) == -1) {
		SLOGE << "Listen error " << errno << ": " << std::strerror(errno);
		stop();
	}

	struct pollfd pfd[2];
	while (mRunning) {
		memset(pfd, 0, sizeof(pfd));
		pfd[0].fd = server_socket;
		pfd[0].events = POLLIN;
		pfd[1].fd = mControlFds[0];
		pfd[1].events = POLLIN;
		
		int ret = poll(pfd, 2, -1);
		if (ret == -1) {
			if (errno != EINTR)
				SLOGE << "CommandLineInterface thread getting poll() error: " << strerror(errno);
			continue;
		} else if (ret == 0) {
			continue; // Timeout not possible
		} else if (pfd[0].revents != POLLIN) {
			continue;
		}
		// Otherwise we have something to accept on our server_socket

		struct sockaddr_un remote;
		auto remote_length = (socklen_t )sizeof(remote);
		int child_socket = accept(server_socket, (struct sockaddr *)&remote, &remote_length);
		if (child_socket == -1) {
			SLOGE << "Accept error " << errno << ": " << std::strerror(errno);
			continue;
		}

		bool finished = false;
		do {
			char buffer[512] = { 0 };
			int n = recv(child_socket, buffer, sizeof(buffer) - 1, 0);
			if (n < 0) {
				SLOGE << "Recv error " << errno << ": " << std::strerror(errno);
				shutdown(child_socket, SHUT_RDWR);
				close(child_socket);
				finished = true;
			} else if (n > 0) {
				SLOGD << "CommandLineInterface " << mName << " received: " << buffer;
				auto split_query = split(buffer, ' ');
				std::string command = split_query.front();
				split_query.erase(split_query.begin());
				parseAndAnswer(child_socket, command, split_query);
				finished = true;
			}
		} while (!finished && mRunning);
	}

	shutdown(server_socket, SHUT_RDWR);
	close(server_socket);
	unlink(path.c_str());
}

GenericEntry* CommandLineInterface::find(GenericStruct *root, std::vector<std::string> &path) {
	std::string elem = path.front();
	path.erase(path.begin());
	for (const auto entry : root->getChildren()) {
		if (!entry || (entry->getName() != elem))
			continue;

		if (path.empty()) {
			return entry;
		} else {
			auto gstruct = dynamic_cast<GenericStruct *>(entry);
			if (gstruct)
				return find(gstruct, path);
			return nullptr;
		}
	}
	return nullptr;
}

std::string CommandLineInterface::printEntry(GenericEntry *entry, bool printHelpInsteadOfValue) {
	auto gstruct = dynamic_cast<GenericStruct *>(entry);
	bool isNode = (gstruct != nullptr);
	std::string answer;
	
	if (printHelpInsteadOfValue) {
		if (isNode)
			answer += "[";
		answer += entry->getName();
		if (isNode)
			answer += "]";
		answer += " : " + entry->getHelp();
	} else {
		if (isNode) {
			answer += "[" + gstruct->getName() + "]";
		} else {
			auto counter = dynamic_cast<StatCounter64 *>(entry);
			if (counter) {
				answer += counter->getName() + " : " + std::to_string(counter->read());
			} else {
				auto value = dynamic_cast<ConfigValue *>(entry);
				if (value)
					answer += value->getName() + " : " + value->get();
			}
		}
	}
	return answer;
}

std::string CommandLineInterface::printSection(GenericStruct *gstruct, bool printHelpInsteadOfValue) {
	std::string answer = "";
	for (const auto child : gstruct->getChildren()) {
		if (child)
			answer += printEntry(child, printHelpInsteadOfValue) + "\r\n";
	}
	return answer;
}

void *CommandLineInterface::threadfunc(void *arg) {
	CommandLineInterface *thiz = reinterpret_cast<CommandLineInterface *>(arg);
	thiz->run();
	return nullptr;
}


ProxyCommandLineInterface::ProxyCommandLineInterface(const std::shared_ptr<Agent> &agent) : CommandLineInterface("proxy"), mAgent(agent) {}

void ProxyCommandLineInterface::handle_registrar_clear_command(unsigned int socket, const std::vector<std::string> &args) {
	if (args.size() < 1) {
		answer(socket, "Error: a SIP address argument is expected for the REGISTRAR_CLEAR command");
		return;
	}

	class ClearListener : public ContactUpdateListener {
	public:
		ClearListener(ProxyCommandLineInterface *cli, unsigned int socket, const std::string &uri)
			: mCli(cli), mSocket(socket), mUri(uri) {}

		void onRecordFound(const shared_ptr<Record> &r) override {
			RegistrarDb::get()->publish(mUri, "");
			mCli->answer(mSocket, "Done: cleared record " + mUri);
		}
		void onError() override {
			mCli->answer(mSocket, "Error: cannot clear record " + mUri);
		}
		void onInvalid() override {
			mCli->answer(mSocket, "Error: cannot clear record " + mUri);
		}
		void onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) override {}

	private:
		ProxyCommandLineInterface *mCli = nullptr;
		unsigned int mSocket = 0;
		std::string mUri;
	};

	std::string arg = args.front();
	auto msg = nta_msg_create(mAgent->getSofiaAgent(), 0);
	auto sip = sip_object(msg);
	sip->sip_from = sip_from_create(msg_home(msg), (url_string_t *)arg.c_str());
	auto listener = std::make_shared<ClearListener>(this, socket, arg);
	RegistrarDb::get()->clear(MsgSip{msg}, listener);
}

void ProxyCommandLineInterface::parseAndAnswer(unsigned int socket, const std::string &command, const std::vector<std::string> &args) {
	if (command == "REGISTRAR_CLEAR")
		handle_registrar_clear_command(socket, args);
	else
		CommandLineInterface::parseAndAnswer(socket, command, args);
}
