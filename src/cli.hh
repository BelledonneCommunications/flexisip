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

#pragma once

#include <future>
#include <string>

#include <pthread.h>
#include <sys/un.h>

#include <flexisip/configmanager.hh>

namespace flexisip {

class CliHandler {
public:
	using HandlerTable = std::list<std::reference_wrapper<CliHandler>>;

	~CliHandler();

	/**
	 * Handles the command and returns the answer, or empty string if it couldn't be handled and another handler should
	 *be tried.
	 * TODO: This function will NOT be called from the main thread. Be careful when writing data.
	 *
	 * @param[in]	command	the command to be handled
	 * @param[in]	args	optional args
	 * @return		the stdout of the command, or "" if this handler doesn't know how to handle it.
	 **/
	virtual std::string handleCommand(const std::string& command, const std::vector<std::string>& args) = 0;

	void registerTo(const std::shared_ptr<HandlerTable>& table);
	void unregister();

private:
	std::weak_ptr<HandlerTable> registration;
};

class Agent;

// Wraps a socket handle to close it automatically on destruction.
class SocketHandle {
public:
	explicit SocketHandle(int handle);
	SocketHandle(SocketHandle&& other);
	SocketHandle(const SocketHandle& other) = delete;
	SocketHandle& operator=(const SocketHandle& other) = delete;
	SocketHandle& operator=(SocketHandle&& other) = delete;
	~SocketHandle();

	int send(std::string_view message) const;
	int recv(char*, size_t length, int flags) const;

protected:
	int mHandle;
};

class CommandLineInterface {
public:
	CommandLineInterface(std::string name,
	                     const std::shared_ptr<ConfigManager>& cfg,
	                     const std::shared_ptr<sofiasip::SuRoot>& root);
	virtual ~CommandLineInterface();

	std::future<void> start();
	void stop();

	void registerHandler(CliHandler& handler);

protected:
	virtual void parseAndAnswer(std::shared_ptr<SocketHandle> socket,
	                            const std::string& command,
	                            const std::vector<std::string>& args);

private:
	static GenericEntry* find(GenericStruct* root, std::vector<std::string>& path);
	static std::string printEntry(GenericEntry* entry, bool printHelpInsteadOfValue);
	static std::string printSection(GenericStruct* gstruct, bool printHelpInsteadOfValue);
	static void* threadFunc(void* arg);

	GenericEntry* getGenericEntry(const std::string& arg) const;
	void handleConfigGet(const std::shared_ptr<SocketHandle>& socket, const std::vector<std::string>& args);
	void handleConfigList(const std::shared_ptr<SocketHandle>& socket, const std::vector<std::string>& args);
	void handleConfigSet(const std::shared_ptr<SocketHandle>& socket, const std::vector<std::string>& args);
	void dispatch(const std::shared_ptr<SocketHandle>& socket,
	              const std::string& command,
	              const std::vector<std::string>& args);
	void run();

	std::string mName;
	pthread_t mThread = 0;
	int mControlFds[2] = {0, 0};
	bool mRunning = false;
	std::shared_ptr<CliHandler::HandlerTable> handlers;
	std::shared_ptr<ConfigManager> mConfigManager;
	std::promise<void> mReady;
	std::shared_ptr<sofiasip::SuRoot> mRoot;
	std::shared_ptr<int> validThisGuard = std::make_shared<int>(1);
	std::string mLogPrefix;
};

class ProxyCommandLineInterface : public CommandLineInterface {
public:
	ProxyCommandLineInterface(const std::shared_ptr<ConfigManager>& cfg, const std::shared_ptr<Agent>& agent);

private:
	void handleRegistrarClear(std::shared_ptr<SocketHandle> socket, const std::vector<std::string>& args);
	void handleRegistrarDelete(std::shared_ptr<SocketHandle> socket, const std::vector<std::string>& args);
	void handleRegistrarUpsert(std::shared_ptr<SocketHandle> socket, const std::vector<std::string>& args);
	void handleRegistrarGet(std::shared_ptr<SocketHandle> socket, const std::vector<std::string>& args);
	void handleRegistrarDump(const std::shared_ptr<SocketHandle>& socket, const std::vector<std::string>& args);
	void parseAndAnswer(std::shared_ptr<SocketHandle> socket,
	                    const std::string& command,
	                    const std::vector<std::string>& args) override;

	std::shared_ptr<Agent> mAgent;
};

} // namespace flexisip