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

#ifndef cli_hh
#define cli_hh

#include <sys/un.h>
#include <pthread.h>
#include <string>
#include <flexisip/configmanager.hh>

class Agent;

class CommandLineInterface {
public:
	CommandLineInterface(const std::string &name);
	virtual ~CommandLineInterface();

	void start();
	void stop();

protected:
	void answer(unsigned int socket, const std::string &message);
	virtual void parseAndAnswer(unsigned int socket, const std::string &command, const std::vector<std::string> &args);

private:
	GenericEntry *get_generic_entry(const std::string &arg) const;
	void handle_config_get_command(unsigned int socket, const std::vector<std::string> &args);
	void handle_config_list_command(unsigned int socket, const std::vector<std::string> &args);
	void handle_config_set_command(unsigned int socket, const std::vector<std::string> &args);
	void run();

	static GenericEntry* find(GenericStruct *root, std::vector<std::string> &path);
	static std::string printEntry(GenericEntry *entry, bool printHelpInsteadOfValue);
	static std::string printSection(GenericStruct *gstruct, bool printHelpInsteadOfValue);
	static void updateLogsVerbosity();

	static void *threadfunc(void *arg);
	
	std::string mName;
	pthread_t mThread = 0;
	int mControlFds[2] = { 0, 0 };
	bool mRunning = false;
};

class ProxyCommandLineInterface : public CommandLineInterface {
public:
	ProxyCommandLineInterface(const std::shared_ptr<Agent> &agent);

private:
	void handle_registrar_clear_command(unsigned int socket, const std::vector<std::string> &args);
	void parseAndAnswer(unsigned int socket, const std::string &command, const std::vector<std::string> &args) override;

	std::shared_ptr<Agent> mAgent;
};

#endif
