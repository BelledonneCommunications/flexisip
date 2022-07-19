/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <map>
#include <string>

#include <sys/types.h>

namespace flexisip {
namespace tester {

/**
 * @brief Instantiate and run an Agent in a child processus by using the fork() routine.
 *
 * This class is use full when a test need to run a second agent with another configuration. This cannot
 * be done in the same processus today because the configuration tree is a singleton object.
 *
 * After instantiating the object with the default constructor, the processus can be created and start by
 * using the spawn() method. Then, several UNIX signal can be send thanks to the methods terminate(), pause() and unpause().
 *
 * The processus is automatically killed if it hasn't been terminated on the object destruction.
 */
class ProxyServerProcess {
public:
	ProxyServerProcess();
	~ProxyServerProcess();

	/**
	 * @brief Create a child processus by forking and run the Agent object.
	 * @param config This map is used to configure the agent. The key is the name
	 * of a parameter to set (e.g. module::Registrar/reg-domains) and the value is
	 * the value to give to the parameter as string.
	 *
	 * @note This method is synchronous i.e. the processus is created and the starting
	 * sequence of the agent is completed when the method returns.
	 */
	void spawn(const std::map<std::string, std::string>& config);

	/**
	 * @brief Kill the processus by sending SIGKILL.
	 * @note This method is synchronous i.e. the processus is actually terminated when the method returns.
	 */
	void terminate();
	/**
	 * @brief Pause the processus by sending SIGSTOP.
	 * @note This method is synchronous i.e. the processus is actually stopped when the method returns.
	 */
	void pause();
	/**
	 * @brief Resume the stopped processus by sending SIGCONT.
	 * @note This method is synchronous i.e. the processus is actually resumed when the method returns.
	 */
	void unpause();

private:
	/**
	 * @brief Must be called by the child process to notify its parent that the Agent is ready.
	 */
	void notify();
	/**
	 * @brief Block the parent processus until a notification is send by the child.
	 */
	void wait();

	// Private attributes
	int mPipeFds[2]; /**< UNIX pipe that allow the parrent processus and its child to communicate. */
	pid_t mPID{0};   /**< PID of the child processus or 0 if we are the child. */
};

} // namespace tester
} // namespace flexisip
