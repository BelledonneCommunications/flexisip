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

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <regex>

#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef ENABLE_TRANSCODER
#include <mediastreamer2/msfactory.h>
#endif

#include <openssl/crypto.h>
#include <openssl/opensslconf.h>
#if defined(OPENSSL_THREADS)
// thread support enabled
#else
// no thread support
#error "No thread support in openssl"
#endif

#include <ortp/ortp.h>

#include <sofia-sip/msg.h>
#include <sofia-sip/sofia_features.h>
#include <sofia-sip/su_log.h>

#include <tclap/CmdLine.h>

#include <flexisip/agent.hh>
#include <flexisip/expressionparser.hh>
#include <flexisip/flexisip-version.h>
#include <flexisip/logmanager.hh>
#include <flexisip/module.hh>
#include <flexisip/sofia-wrapper/su-root.hh>

#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif
#ifndef CONFIG_DIR
#define CONFIG_DIR
#endif
#ifndef FLEXISIP_GIT_VERSION
#define FLEXISIP_GIT_VERSION "undefined"
#endif

#include "cli.hh"
#include "configdumper.hh"
#include "etchosts.hh"
#include "monitor.hh"
#include "stun.hh"

#ifdef ENABLE_CONFERENCE
#include "conference/conference-server.hh"
#include "registration-events/server.hh"
#endif
#ifdef ENABLE_B2BUA
#include "b2bua/b2bua-server.hh"
#endif // ENABLE_B2BUA
#ifdef ENABLE_PRESENCE
#include "presence/presence-longterm.hh"
#include "presence/presence-server.hh"
#endif

#ifdef ENABLE_SNMP
#include "snmp-agent.h"
#endif

static int run = 1;
static int pipe_wdog_flexisip[2] = {
    -1}; // This is the pipe that flexisip will write to to signify it has started to the Watchdog
static pid_t flexisip_pid = -1;
static pid_t monitor_pid = -1;
static std::shared_ptr<sofiasip::SuRoot> root{};

#if ENABLE_PRESENCE
static std::shared_ptr<flexisip::PresenceServer> presenceServer;
#endif // ENABLE_PRESENCE
#if ENABLE_CONFERENCE
static std::shared_ptr<flexisip::ConferenceServer> conferenceServer;
static std::shared_ptr<flexisip::RegistrationEvent::Server> regEventServer;
#endif // ENABLE_CONFERENCE
#if ENABLE_B2BUA
static std::shared_ptr<flexisip::B2buaServer> b2buaServer;
#endif // ENABLE_B2BUA

using namespace std;
using namespace flexisip;

unsigned long threadid_cb() {
	return (unsigned long)pthread_self();
}

void locking_function(int mode, int n, [[maybe_unused]] const char* file, [[maybe_unused]] int line) {
	static mutex* mutextab = NULL;
	if (mutextab == NULL) mutextab = new mutex[CRYPTO_num_locks()];
	if (mode & CRYPTO_LOCK) mutextab[n].lock();
	else mutextab[n].unlock();
}

static void setOpenSSLThreadSafe() {
	CRYPTO_set_id_callback(&threadid_cb);
	CRYPTO_set_locking_callback(&locking_function);
}

static void flexisip_stop(int signum) {
	if (flexisip_pid > 0) {
		// We can't log from the parent process
		// LOGD("Watchdog received quit signal...passing to child.");
		/*we are the watchdog, pass the signal to our child*/
		kill(flexisip_pid, signum);
	} else if (run != 0) {
		// LOGD("Received quit signal...");

		run = 0;
		if (root) root->quit();
	} // else nop
}

static void flexisip_reopen_log_files([[maybe_unused]] int signum) {
	LogManager::get().reopenFiles();
}

static void sofiaLogHandler(void*, const char* fmt, va_list ap) {
	// remove final \n from sofia
	if (fmt) {
		char* copy = strdup(fmt);
		copy[strlen(copy) - 1] = '\0';
		LOGDV(copy, ap);
		free(copy);
	}
}

static std::map<msg_t*, string> msg_map;

static void flexisip_msg_create(msg_t* msg) {
	msg_map[msg] = "";
	LOGE("New <-> msg %p", msg);
}

static void flexisip_msg_destroy(msg_t* msg) {
	auto it = msg_map.find(msg);
	if (it != msg_map.end()) {
		msg_map.erase(it);
	}
}

static void dump_remaining_msgs() {
	LOGE("### Remaining messages: %lu", (unsigned long)msg_map.size());
	for (auto it = msg_map.begin(); it != msg_map.end(); ++it) {
		LOGE("### \t- %p\n", it->first);
	}
}

static int getSystemFdLimit() {
	static int max_sys_fd = -1;
	if (max_sys_fd == -1) {
#ifdef __linux
		char tmp[256] = {0}; // make valgrind happy
		int fd = open("/proc/sys/fs/file-max", O_RDONLY);
		if (fd != -1) {
			if (read(fd, tmp, sizeof(tmp)) > 0) {
				int val = 0;
				if (sscanf(tmp, "%i", &val) == 1) {
					max_sys_fd = val;
					LOGI("System wide maximum number of file descriptors is %i", max_sys_fd);
				}
			}
			close(fd);
			fd = open("/proc/sys/fs/nr_open", O_RDONLY);
			if (fd != -1) {
				if (read(fd, tmp, sizeof(tmp)) > 0) {
					int val = 0;
					if (sscanf(tmp, "%i", &val) == 1) {
						LOGI("System wide maximum number open files is %i", val);
						if (val < max_sys_fd) {
							max_sys_fd = val;
						}
					}
				}
				close(fd);
			}
		}
#else
		LOGW("Guessing of system wide fd limit is not implemented.");
		max_sys_fd = 2048;
#endif
	}
	return max_sys_fd;
}

static void increase_fd_limit(void) {
	struct rlimit lm;
	if (getrlimit(RLIMIT_NOFILE, &lm) == -1) {
		LOGE("getrlimit(RLIMIT_NOFILE) failed: %s", strerror(errno));
	} else {
		unsigned new_limit = (unsigned)getSystemFdLimit();
		int old_lim = (int)lm.rlim_cur;
		LOGI("Maximum number of open file descriptors is %i, limit=%i, system wide limit=%i", (int)lm.rlim_cur,
		     (int)lm.rlim_max, getSystemFdLimit());

		if (lm.rlim_cur < new_limit) {
			lm.rlim_cur = lm.rlim_max = new_limit;
			if (setrlimit(RLIMIT_NOFILE, &lm) == -1) {
				LOGE("setrlimit(RLIMIT_NOFILE) failed: %s. Limit of number of file descriptors is low (%i).",
				     strerror(errno), old_lim);
				LOGE("Flexisip will not be able to process a big number of calls.");
			}
			if (getrlimit(RLIMIT_NOFILE, &lm) == 0) {
				LOGI("Maximum number of file descriptor set to %i.", (int)lm.rlim_cur);
			}
		}
	}
}

/* Allows to detach the watchdog from the PTY so that we don't get traces clobbering the terminal */
static void detach() {
	int fd;
	setsid();
	fd = open("/dev/null", O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "Could not open /dev/null\n");
		exit(-1);
	}
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	close(fd);
}

static void makePidFile(const string& pidfile) {
	if (!pidfile.empty()) {
		FILE* f = fopen(pidfile.c_str(), "w");
		if (f) {
			fprintf(f, "%i", getpid());
			fclose(f);
		} else {
			LOGE("Could not write pid file [%s]", pidfile.c_str());
		}
	}
}

static void set_process_name([[maybe_unused]] const string& process_name) {
#ifdef PR_SET_NAME
	if (prctl(PR_SET_NAME, process_name.c_str(), NULL, NULL, NULL) == -1) {
		LOGW("prctl() failed: %s", strerror(errno));
	}
#endif
}

static void forkAndDetach(const string& pidfile, bool auto_respawn, bool startMonitor, const string& functionName) {
	int pipe_launcher_wdog[2];
	int err = pipe(pipe_launcher_wdog);
	bool launcherExited = false;
	if (err == -1) {
		LOGE("Could not create pipes: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Creation of the watch-dog process */
	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Could not fork: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (pid == 0) {
		/* We are in the watch-dog process */
		uint8_t buf[4];
		close(pipe_launcher_wdog[0]);
		set_process_name("flexisipwd-" + functionName);

	/* Creation of the flexisip process */
	fork_flexisip:
		err = pipe(pipe_wdog_flexisip);
		if (err == -1) {
			LOGE("Could not create pipes: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		flexisip_pid = fork();
		if (flexisip_pid < 0) {
			fprintf(stderr, "Could not fork: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (flexisip_pid == 0) {

			/* This is the real flexisip process now.
			 * We can proceed with real start
			 */
			close(pipe_wdog_flexisip[0]);
			set_process_name("flexisip-" + functionName);
			makePidFile(pidfile);
			return;
		} else {
			LOGI("[WDOG] Flexisip PID: %d", flexisip_pid);
		}

		/*
		 * We are in the watch-dog process again
		 * Waiting for successful initialisation of the flexisip process
		 */
		close(pipe_wdog_flexisip[1]);
		err = read(pipe_wdog_flexisip[0], buf, sizeof(buf));
		if (err == -1 || err == 0) {
			if (err == -1) LOGE("[WDOG] Read error from flexisip : %s", strerror(errno));
			close(pipe_launcher_wdog[1]); // close launcher pipe to signify the error
			exit(EXIT_FAILURE);
		}
		close(pipe_wdog_flexisip[0]);

	/*
	 * Flexisip has successfully started.
	 * We can now start the Flexisip monitor if it is requierd
	 */
	fork_monitor:
		if (startMonitor) {
			int pipe_wd_mo[2];
			err = pipe(pipe_wd_mo);
			if (err == -1) {
				LOGE("Cannot create pipe. %s", strerror(errno));
				kill(flexisip_pid, SIGTERM);
				exit(EXIT_FAILURE);
			}
			monitor_pid = fork();
			if (monitor_pid < 0) {
				fprintf(stderr, "Could not fork: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (monitor_pid == 0) {
				/* We are in the monitor process */
				set_process_name("flexisip_mon");
				close(pipe_launcher_wdog[1]);
				close(pipe_wd_mo[0]);
				Monitor::exec(pipe_wd_mo[1]);
				LOGE("Fail to launch the Flexisip monitor");
				exit(EXIT_FAILURE);
			}
			/* We are in the watchdog process */
			close(pipe_wd_mo[1]);
			err = read(pipe_wd_mo[0], buf, sizeof(buf));
			if (err == -1 || err == 0) {
				LOGE("[WDOG] Read error from Monitor process, killing flexisip");
				kill(flexisip_pid, SIGTERM);
				exit(EXIT_FAILURE);
			}
			close(pipe_wd_mo[0]);
		}

		/*
		 * We are in the watchdog process once again, and all went well, tell the launcher that it can exit
		 */

		if (!launcherExited && write(pipe_launcher_wdog[1], "ok", 3) == -1) {
			LOGE("[WDOG] Write to pipe failed, exiting");
			exit(EXIT_FAILURE);
		} else {
			close(pipe_launcher_wdog[1]);
			launcherExited = true;
		}

		/* Detach ourselves from the PTY. */
		detach();

		/*
		 * This loop aims to restart childs of the watchdog process
		 * when they have a crash
		 */
		while (true) {
			int status = 0;
			pid_t retpid = wait(&status);
			if (retpid > 0) {
				if (retpid == flexisip_pid) {
					if (startMonitor) kill(monitor_pid, SIGTERM);
					if (WIFEXITED(status)) {
						if (WEXITSTATUS(status) == RESTART_EXIT_CODE) {
							LOGI("Flexisip restart to apply new config...");
							sleep(1);
							goto fork_flexisip;
						} else {
							LOGD("Flexisip exited normally");
							exit(EXIT_SUCCESS);
						}
					} else if (auto_respawn) {
						LOGE("Flexisip apparently crashed, respawning now...");
						sleep(1);
						goto fork_flexisip;
					}
				} else if (retpid == monitor_pid) {
					LOGE("The Flexisip monitor has crashed or has been illegally terminated. Restarting now");
					sleep(1);
					goto fork_monitor;
				}
			} else if (errno != EINTR) {
				LOGE("waitpid() error: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
	} else {
		/* This is the initial process.
		 * It should block until flexisip has started sucessfully or rejected to start.
		 */
		LOGD("[LAUNCHER] Watchdog PID: %d", pid);
		uint8_t buf[4];
		// we don't need the write side of the pipe:
		close(pipe_launcher_wdog[1]);

		// Wait for WDOG to tell us "ok" if all went well, or close the pipe if flexisip failed somehow
		err = read(pipe_launcher_wdog[0], buf, sizeof(buf));
		if (err == -1 || err == 0) {
			// pipe was closed, flexisip failed to start -> exit with failure
			LOGE("[LAUNCHER] Flexisip failed to start.");
			exit(EXIT_FAILURE);
		} else {
			// pipe written to, flexisip was OK
			LOGD("[LAUNCHER] Flexisip started correctly: exit");
			exit(EXIT_SUCCESS);
		}
	}
}

static void depthFirstSearch(string& path, GenericEntry* config, list<string>& allCompletions) {
	auto gStruct = dynamic_cast<GenericStruct*>(config);
	if (gStruct) {
		string newpath;
		if (!path.empty()) newpath += path + "/";
		if (config->getName() != "flexisip") newpath += config->getName();
		for (auto it = gStruct->getChildren().cbegin(); it != gStruct->getChildren().cend(); ++it) {
			depthFirstSearch(newpath, it->get(), allCompletions);
		}
		return;
	}

	auto cValue = dynamic_cast<ConfigValue*>(config);
	if (cValue) {
		string completion;
		if (!path.empty()) completion += path + "/";
		completion += cValue->getName();
		allCompletions.push_back(completion);
	}
}

static void dump_config(const std::shared_ptr<sofiasip::SuRoot>& root,
                        const std::string& dump_cfg_part,
                        bool with_experimental,
                        bool dumpDefault,
                        const string& format) {
	GenericManager::get()->applyOverrides(true);
	auto* pluginsDirEntry = GenericManager::get()->getGlobal()->get<ConfigString>("plugins-dir");
	if (pluginsDirEntry->get().empty()) {
		pluginsDirEntry->set(DEFAULT_PLUGINS_DIR);
	}

	auto a = make_shared<Agent>(root);
	if (!dumpDefault) a->loadConfig(GenericManager::get());

	auto* rootStruct = GenericManager::get()->getRoot();
	if (dump_cfg_part != "all") {
		smatch m;
		rootStruct = dynamic_cast<GenericStruct*>(rootStruct->find(dump_cfg_part));
		if (rootStruct == nullptr) {
			cerr << "Couldn't find node " << dump_cfg_part << endl;
			exit(EXIT_FAILURE);
		}
		if (regex_match(dump_cfg_part, m, regex("^module::(.*)$"))) {
			const auto& moduleName = m[1];
			const auto& module = a->findModule(moduleName);
			if (module && module->getClass() == ModuleClass::Experimental && !with_experimental) {
				cerr << "Module " << moduleName
				     << " is experimental, not returning anything. To override, specify '--show-experimental'" << endl;
				exit(EXIT_FAILURE);
			}
		}
	}

	unique_ptr<ConfigDumper> dumper{};
	if (format == "tex") {
		dumper = make_unique<TexFileConfigDumper>(rootStruct);
	} else if (format == "doku") {
		dumper = make_unique<DokuwikiConfigDumper>(rootStruct);
	} else if (format == "file") {
		auto fileDumper = make_unique<FileConfigDumper>(rootStruct);
		fileDumper->setMode(dumpDefault ? FileConfigDumper::Mode::DefaultValue
		                                : FileConfigDumper::Mode::DefaultIfUnset);
		dumper = move(fileDumper);
	} else if (format == "media") {
		dumper = make_unique<MediaWikiConfigDumper>(rootStruct);
	} else if (format == "xwiki") {
		dumper = make_unique<XWikiConfigDumper>(rootStruct);
	} else {
		cerr << "Invalid output format '" << format << "'" << endl;
		exit(EXIT_FAILURE);
	}
	dumper->setDumpExperimentalEnabled(with_experimental);
	dumper->dump(cout);
	exit(EXIT_SUCCESS);
}

static void list_sections(bool moduleOnly = false) {
	const string modulePrefix{"module::"};
	auto a = make_shared<Agent>(root);
	for (const auto& child : GenericManager::get()->getRoot()->getChildren()) {
		if (!moduleOnly || child->getName().compare(0, modulePrefix.size(), modulePrefix) == 0) {
			cout << child->getName() << endl;
		}
	}
}

static const string
getFunctionName(bool startProxy, bool startPresence, bool startConference, bool regEvent, bool b2bua) {
	string functions;
	if (startProxy) functions = "proxy";
	if (startPresence) functions += ((functions.empty()) ? "" : "+") + string("presence");
	if (startConference) functions += ((functions.empty()) ? "" : "+") + string("conference");
	if (regEvent) functions += ((functions.empty()) ? "" : "+") + string("regevent");
	if (b2bua) functions += ((functions.empty()) ? "" : "+") + string("b2bua");

	return (functions.empty()) ? "none" : functions;
}

static void notifyWatchDog() {
	static bool notified = false;
	if (!notified) {
		if (write(pipe_wdog_flexisip[1], "ok", 3) == -1) {
			LOGF("Failed to write starter pipe: %s", strerror(errno));
		}
		close(pipe_wdog_flexisip[1]);
		notified = true;
	}
}

static string version() {
	ostringstream version;
	version << FLEXISIP_GIT_VERSION "\n";

	version << "sofia-sip version " SOFIA_SIP_VERSION "\n";
	version << "\nCompiled with:\n";
#if ENABLE_SNMP
	version << "- SNMP\n";
#endif
#if ENABLE_TRANSCODER
	version << "- Transcoder\n";
#endif
#if ENABLE_REDIS
	version << "- Redis\n";
#endif
#if ENABLE_SOCI
	version << "- Soci\n";
#endif
#if ENABLE_PROTOBUF
	version << "- Protobuf\n";
#endif
#if ENABLE_PRESENCE
	version << "- Presence\n";
#endif
#if ENABLE_CONFERENCE
	version << "- Conference\n";
	version << "- RegEvent\n";
#endif
#ifdef ENABLE_B2BUA
	version << "- B2BUA\n";
#endif

	return version.str();
}

static string getPkcsPassphrase(TCLAP::ValueArg<string>& pkcsFile) {
	string passphrase;
	if (!pkcsFile.getValue().empty()) {
		ifstream dacb(pkcsFile.getValue());
		if (!dacb.is_open()) {
			SLOGE << "Can't open pkcs passphrase file : " << pkcsFile.getValue();
		} else {
			while (!dacb.eof()) {
				dacb >> passphrase;
			}
		}
	}
	return passphrase;
}

int main(int argc, char* argv[]) {
	shared_ptr<Agent> a;
	StunServer* stun = NULL;
	unique_ptr<CommandLineInterface> proxy_cli;
#ifdef ENABLE_PRESENCE
	unique_ptr<CommandLineInterface> presence_cli;
#endif
#ifdef ENABLE_SNMP
	unique_ptr<SnmpAgent> snmpAgent;
#endif
	bool debug;
	bool user_errors = false;

	string versionString = version();
	// clang-format off
	TCLAP::CmdLine cmd("", ' ', versionString);
	TCLAP::ValueArg<string>     functionName("", "server", 		"Specify the server function to operate: 'proxy',"
#if ENABLE_PRESENCE
	" 'presence',"
#endif
#if ENABLE_CONFERENCE
	" 'regevent', 'conference',"
#endif
#ifdef ENABLE_B2BUA
	" 'b2bua',"
#endif
	" or 'all'.", TCLAP::ValueArgOptional, "", "server function", cmd);

#define DEFAULT_CONFIG_FILE CONFIG_DIR "/flexisip.conf"
	TCLAP::ValueArg<string>     configFile("c", "config", 			"Specify the location of the configuration file. Default is " DEFAULT_CONFIG_FILE, TCLAP::ValueArgOptional, DEFAULT_CONFIG_FILE, "file", cmd);

	TCLAP::SwitchArg            daemonMode("",  "daemon", 			"Launch in daemon mode.", cmd);
	TCLAP::SwitchArg              useDebug("d", "debug", 			"Force output of all logs, including debug logs, to the terminal (does not affect the log level applied to log files).", cmd);
	TCLAP::ValueArg<string>        pidFile("p", "pidfile", 			"PID file location, used when running in daemon mode.", TCLAP::ValueArgOptional, "", "file", cmd);
	TCLAP::SwitchArg             useSyslog("",  "syslog", 			"Use syslog for logging.", cmd);

	TCLAP::ValueArg<string>  transportsArg("t", "transports", 		"The list of transports to handle (overrides the ones defined in the configuration file).", TCLAP::ValueArgOptional, "", "sips:* sip:*", cmd);



	TCLAP::ValueArg<string>    dumpDefault("",  "dump-default",		"Dump default config, with specifier for the module to dump. Use 'all' to dump all modules, or 'MODULENAME' to dump "
										   							"a specific module. For instance, to dump the Router module default config, "
																	"issue 'flexisip --dump-default module::Router.", TCLAP::ValueArgOptional, "", "all", cmd);
	TCLAP::SwitchArg               dumpAll("",  "dump-all-default", "Will dump all the configuration. This is equivalent to '--dump-default all'. This option may be combined with "
																	"'--set global/plugins=<plugin_list>' to also generate the settings of listed plugins.", cmd);
	TCLAP::ValueArg<string>     dumpFormat("",  "dump-format",		"Select the format in which the dump-default will print. The default is 'file'. Possible values are: "
																	"file, tex, doku, media, xwiki.", TCLAP::ValueArgOptional, "file", "file", cmd);


	TCLAP::SwitchArg           listModules("",  "list-modules", 	"Will print a list of available modules. This is useful if you want to combine with --dump-default "
										   							"to have specific documentation for a module.", cmd);

	TCLAP::SwitchArg           listSections("",  "list-sections", 	"Will print a list of available sections. This is useful if you want to combine with --dump-default "
										   							"to have specific documentation for a section.", cmd);
	TCLAP::SwitchArg           rewriteConf("",  "rewrite-config",   "Load the configuration file and dump a new one on stdout, adding the new settings and updating documentations. "
	                                                                "All the existing settings are kept even if they are equal to the default value and the default value has changed.", cmd);
	TCLAP::SwitchArg              dumpMibs("",  "dump-mibs", 		"Will dump the MIB files for Flexisip performance counters and other related SNMP items.", cmd);
	TCLAP::ValueArg<string>     pkcsFile("", "p12-passphrase-file", "Specify the location of the pkcs12 passphrase file.", TCLAP::ValueArgOptional,"", "file", cmd);
	TCLAP::SwitchArg   displayExperimental("",  "show-experimental","Use in conjunction with --dump-default: will dump the configuration for a module even if it is marked as experiemental.", cmd);

	/* Overriding values */
	TCLAP::ValueArg<string>  listOverrides("",  "list-overrides",	"List the configuration values that you can override. Useful in conjunction with --set. "
																	"Pass a module to specify the module for which to dump the available values. Use 'all' to get all possible overrides.",
										   TCLAP::ValueArgOptional, "", "module", cmd);

	TCLAP::MultiArg<string> overrideConfig("s", "set", 				"Allows to override the configuration file setting. Use --list-overrides to get a list of values that you can override.",
										   TCLAP::ValueArgOptional, "global/debug=true", cmd);

	TCLAP::MultiArg<string>  hostsOverride("",  "hosts",			"Overrides a host address by passing it. You can use this flag multiple times. "
																	"Also, you can remove an association by providing an empty value: '--hosts myhost='.",
										   TCLAP::ValueArgOptional, "host=ip", cmd);
	TCLAP::SwitchArg           trackAllocs("",  "track-allocations", "Tracks allocations of SIP messages, only use with caution.", cmd);

	// clang-format on

	try {
		// Try parsing input
		cmd.parse(argc, argv);
		debug = useDebug.getValue();

	} catch (TCLAP::ArgException& e) {

		cerr << "Error parsing arguments: " << e.error() << " for arg " << e.argId() << endl;
		exit(EXIT_FAILURE);
	}

	map<string, string> oset;
	for (const string& kv : overrideConfig.getValue()) {
		auto equal = find(kv.cbegin(), kv.cend(), '=');
		if (equal != kv.cend()) {
			oset[string(kv.cbegin(), equal)] = string(equal + 1, kv.cend());
		}
	}

	// Instanciate the main loop and set signal callbacks
	root = make_shared<sofiasip::SuRoot>();
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, flexisip_stop);
	signal(SIGINT, flexisip_stop);
	signal(SIGHUP, flexisip_reopen_log_files);

	// Instanciate the Generic manager
	GenericManager* cfg = GenericManager::get();
	cfg->setOverrideMap(oset);

	// list default config and exit
	std::string module = dumpDefault.getValue();
	if (dumpAll) {
		module = "all";
	}

	if (module.length() != 0) {
		dump_config(root, module, displayExperimental, true, dumpFormat.getValue());
	}

	// list all mibs and exit
	if (dumpMibs) {
		a = make_shared<Agent>(root);
		cout << MibDumper(GenericManager::get()->getRoot());
		return EXIT_SUCCESS;
	}

	// list modules and exit
	if (listModules) {
		list_sections(true);
		return EXIT_SUCCESS;
	}

	// list sections and exit
	if (listSections) {
		list_sections();
		return EXIT_SUCCESS;
	}

	// list the overridable values and exit
	if (listOverrides.getValue().length() != 0) {
		a = make_shared<Agent>(root);
		list<string> allCompletions;
		allCompletions.push_back("nosnmp");

		string empty;
		string& filter = listOverrides.getValue();

		depthFirstSearch(empty, GenericManager::get()->getRoot(), allCompletions);

		for (auto it = allCompletions.cbegin(); it != allCompletions.cend(); ++it) {
			if (filter == "all") {
				cout << *it << "\n";
			} else if (0 == it->compare(0, filter.length(), filter)) {
				cout << *it << "\n";
			}
		}
		return EXIT_SUCCESS;
	}

	if (cfg->load(configFile.getValue()) == -1) {
		fprintf(stderr,
		        "Flexisip version %s\n"
		        "No configuration file found at %s.\nPlease specify a valid configuration file.\n"
		        "A default flexisip.conf.sample configuration file should be installed in " CONFIG_DIR "\n"
		        "Please edit it and restart flexisip when ready.\n"
		        "Alternatively a default configuration sample file can be generated at any time using "
		        "'--dump-default all' option.\n",
		        versionString.c_str(), configFile.getValue().c_str());
		return -1;
	}

	if (rewriteConf) {
		dump_config(root, "all", displayExperimental, false, "file");
	}

	// if --debug is given, enable user-errors logs as well.
	if (debug) user_errors = true;

	bool dump_cores = cfg->getGlobal()->get<ConfigBoolean>("dump-corefiles")->read();

	bool startProxy = false;
	bool startPresence = false;
	bool startConference = false;
	bool startRegEvent = false;
	bool startB2bua = false;

	if (functionName.getValue() == "proxy") {
		startProxy = true;
	} else if (functionName.getValue() == "presence") {
		startPresence = true;
#ifndef ENABLE_PRESENCE
		LOGF("Flexisip was compiled without presence server extension.");
#endif
	} else if (functionName.getValue() == "conference") {
		startConference = true;
#ifndef ENABLE_CONFERENCE
		LOGF("Flexisip was compiled without conference server extension.");
#endif
	} else if (functionName.getValue() == "regevent") {
		startRegEvent = true;
#ifndef ENABLE_CONFERENCE
		LOGF("Flexisip was compiled without regevent server extension.");
#endif
	} else if (functionName.getValue() == "b2bua") {
		startB2bua = true;
#ifndef ENABLE_B2BUA
		LOGF("Flexisip was compiled without back-to-back user agent server extension.");
#endif
	} else if (functionName.getValue() == "all") {
		startPresence = true;
		startProxy = true;
		startConference = true;
		startRegEvent = true;
		startB2bua = true;
	} else if (functionName.getValue().empty()) {
		auto default_servers = cfg->getGlobal()->get<ConfigStringList>("default-servers");
		if (default_servers->contains("proxy")) {
			startProxy = true;
		}
		if (default_servers->contains("presence")) {
			startPresence = true;
		}
		if (default_servers->contains("conference")) {
			startConference = true;
		}
		if (default_servers->contains("regevent")) {
			startRegEvent = true;
		}
		if (default_servers->contains("b2bua")) {
			startB2bua = true;
		}
		if (!startPresence && !startProxy && !startConference) {
			LOGF("Bad default-servers definition '%s'.", default_servers->get().c_str());
		}
	} else {
		LOGF("There is no server function '%s'.", functionName.getValue().c_str());
	}
	string fName = getFunctionName(startProxy, startPresence, startConference, startRegEvent, startB2bua);
	// Initialize
	std::string log_level = cfg->getGlobal()->get<ConfigString>("log-level")->read();
	std::string syslog_level = cfg->getGlobal()->get<ConfigString>("syslog-level")->read();
	if (!user_errors) user_errors = cfg->getGlobal()->get<ConfigBoolean>("user-errors-logs")->read();

	ortp_init();
	su_init();
	/*tell parser to support extra headers */
	sip_update_default_mclass(sip_extend_mclass(NULL));

	if (dump_cores) {
		/*enable core dumps*/
		struct rlimit lm;
		lm.rlim_cur = RLIM_INFINITY;
		lm.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE, &lm) == -1) {
			LOGE("Cannot enable core dump, setrlimit() failed: %s", strerror(errno));
		}
	}

	if (hostsOverride.getValue().size() != 0) {
		auto hosts = hostsOverride.getValue();
		auto etcResolver = EtcHostsResolver::get();

		for (auto it = hosts.begin(); it != hosts.end(); ++it) {
			size_t pos = it->find("=");
			if (pos != it->npos) {
				etcResolver->setHost(it->substr(0, pos), it->substr(pos + 1));
			}
		}
	}

	su_log_redirect(NULL, sofiaLogHandler, NULL);
	if (debug || log_level == "debug") {
		su_log_set_level(NULL, 9);
	}
	/*read the pkcs passphrase if any from the fifo, and keep it in memory*/
	auto passphrase = getPkcsPassphrase(pkcsFile);

	/*
	 * Perform the fork of the watchdog, followed by the fork of the worker daemon, in forkAndDetach().
	 * NEVER NEVER create pthreads before this point : threads do not survive the fork below !!!!!!!!!!
	 */
	bool monitorEnabled = cfg->getRoot()->get<GenericStruct>("monitor")->get<ConfigBoolean>("enabled")->read();
	if (daemonMode) {
		/*now that we have successfully loaded the config, there is nothing that can prevent us to start (normally).
		So we can detach.*/
		bool autoRespawn = cfg->getGlobal()->get<ConfigBoolean>("auto-respawn")->read();
		if (!startProxy) monitorEnabled = false;
		forkAndDetach(pidFile.getValue(), autoRespawn, monitorEnabled, fName);
	} else if (pidFile.getValue().length() != 0) {
		// not daemon but we want a pidfile anyway
		makePidFile(pidFile.getValue());
	}

	/*
	 * Log initialisation.
	 * This must be done after forking in order the log file be reopen after respawn should Flexisip crash.
	 * The condition intent to avoid log initialisation should the user have passed command line options that doesn't
	 * require to start the server e.g. dumping default configuration file.
	 */
	if (!dumpDefault.getValue().length() && !listOverrides.getValue().length() && !listModules && !listSections &&
	    !dumpMibs && !dumpAll) {
		if (cfg->getGlobal()->get<ConfigByteSize>("max-log-size")->read() !=
		    static_cast<ConfigByteSize::ValueType>(-1)) {
			LOGF("Setting 'global/max-log-size' parameter has been forbidden since log size control was delegated to "
			     "logrotate. Please edit /etc/logrotate.d/flexisip-logrotate for log rotation customization.");
		}

		const auto& logFilename = cfg->getGlobal()->get<ConfigString>("log-filename")->read();

		LogManager::Parameters logParams{};
		logParams.root = root->getCPtr();
		logParams.logDirectory = cfg->getGlobal()->get<ConfigString>("log-directory")->read();
		logParams.logFilename = regex_replace(logFilename, regex{"\\{server\\}"}, fName);
		logParams.level = debug ? BCTBX_LOG_DEBUG : LogManager::get().logLevelFromName(log_level);
		logParams.enableSyslog = useSyslog;
		logParams.syslogLevel = LogManager::get().logLevelFromName(syslog_level);
		logParams.enableStdout = debug && !daemonMode; // No need to log to stdout in daemon mode.
		logParams.enableUserErrors = user_errors;
		LogManager::get().initialize(logParams);
		LogManager::get().setContextualFilter(cfg->getGlobal()->get<ConfigString>("contextual-log-filter")->read());
		LogManager::get().setContextualLevel(
		    LogManager::get().logLevelFromName(cfg->getGlobal()->get<ConfigString>("contextual-log-level")->read()));
		try {
			MsgSip::setShowBodyFor(cfg->getGlobal()->get<ConfigString>("show-body-for")->read());
		} catch (const invalid_argument& e) {
			LOGF("Setting 'global/show-body-for' must only contains sip method names, whitespace separated. %s",
			     e.what());
		}
	} else {
		LogManager::get().disable();
	}

	/*
	 * From now on, we are a flexisip daemon, that is a process that will run proxy, presence, regevent or conference
	 * server.
	 */
	LOGN("Starting flexisip %s-server version %s", fName.c_str(), FLEXISIP_GIT_VERSION);
	GenericManager::get()->sendTrap("Flexisip " + fName + "-server starting");

	increase_fd_limit();

	/*
	 * We create an Agent in all cases, because it will declare config items that are necessary for presence server to
	 * run.
	 */
	a = make_shared<Agent>(root);
	setOpenSSLThreadSafe();
	a->loadConfig(cfg);

	if (startProxy) {
		a->start(transportsArg.getValue(), passphrase);
#ifdef ENABLE_SNMP
		bool snmpEnabled = cfg->getGlobal()->get<ConfigBoolean>("enable-snmp")->read();
		if (snmpEnabled) {
			snmpAgent.reset(new SnmpAgent(*a, *cfg, oset));
		}
#endif

		cfg->applyOverrides(true); // using default + overrides

		// Create cached test accounts for the Flexisip monitor if necessary
		if (monitorEnabled) {
			try {
				Monitor::createAccounts();
			} catch (const FlexisipException& e) {
				LOGE("Could not create test accounts for the monitor. %s", e.str().c_str());
			}
		}

		if (daemonMode) {
			notifyWatchDog();
		}

		if (cfg->getRoot()->get<GenericStruct>("stun-server")->get<ConfigBoolean>("enabled")->read()) {
			stun = new StunServer(cfg->getRoot()->get<GenericStruct>("stun-server")->get<ConfigInt>("port")->read());
			stun->start();
		}

		proxy_cli = unique_ptr<CommandLineInterface>(new ProxyCommandLineInterface(a));
		proxy_cli->start();

		if (trackAllocs) msg_set_callbacks(flexisip_msg_create, flexisip_msg_destroy);
	}

	if (startPresence) {
#ifdef ENABLE_PRESENCE
		bool enableLongTermPresence =
		    (cfg->getRoot()->get<GenericStruct>("presence-server")->get<ConfigBoolean>("long-term-enabled")->read());
		presenceServer = make_shared<flexisip::PresenceServer>(root);
		if (enableLongTermPresence) {
			auto presenceLongTerm = make_shared<flexisip::PresenceLongterm>(presenceServer->getBelleSipMainLoop());
			presenceServer->addPresenceInfoObserver(presenceLongTerm);
		}
		if (daemonMode) {
			notifyWatchDog();
		}
		try {
			presenceServer->init();
		} catch (FlexisipException& e) {
			/* Catch the presence server exception, which is generally caused by a failure while binding the SIP
			 * listening points.
			 * Since it prevents from starting and it is not a crash, it shall be notified to the user with LOGF*/
			LOGF("Fail to start flexisip presence server");
		}

		presence_cli = unique_ptr<CommandLineInterface>(new CommandLineInterface("presence"));
		presence_cli->start();
#endif
	}

	if (startConference) {
#ifdef ENABLE_CONFERENCE
		conferenceServer = make_shared<flexisip::ConferenceServer>(a->getPreferredRoute(), root);
		if (daemonMode) {
			notifyWatchDog();
		}
		try {
			conferenceServer->init();
		} catch (FlexisipException& e) {
			/* Catch the conference server exception, which is generally caused by a failure while binding the SIP
			 * listening points.
			 * Since it prevents from starting and it is not a crash, it shall be notified to the user with LOGF*/
			LOGF("Fail to start flexisip conference server");
		}
#endif // ENABLE_CONFERENCE
	}

	if (startRegEvent) {
#ifdef ENABLE_CONFERENCE
		regEventServer = make_shared<flexisip::RegistrationEvent::Server>(root);
		if (daemonMode) {
			notifyWatchDog();
		}
		try {
			regEventServer->init();
		} catch (FlexisipException& e) {
			LOGF("Fail to start flexisip registration event server");
		}
#endif // ENABLE_CONFERENCE
	}

	if (startB2bua) {
#if ENABLE_B2BUA
		b2buaServer = make_shared<flexisip::B2buaServer>(root);
		if (daemonMode) {
			notifyWatchDog();
		}
		try {
			b2buaServer->init();
		} catch (FlexisipException& e) {
			LOGF("Fail to start flexisip back to back user agent server");
		}
#endif // ENABLE_B2BUA
	}

	if (run) root->run();

	a->unloadConfig();
	a.reset();
#ifdef ENABLE_PRESENCE
	presence_cli = nullptr;
	if (presenceServer) presenceServer->stop();
	presenceServer.reset();
#endif // ENABLE_PRESENCE

#ifdef ENABLE_CONFERENCE
	if (conferenceServer) conferenceServer->stop();
	conferenceServer.reset();

	if (regEventServer) regEventServer->stop();
#endif // ENABLE_CONFERENCE
#if ENABLE_B2BUA
	if (b2buaServer) b2buaServer->stop();
#endif // ENABLE_B2BUA

	if (stun) {
		stun->stop();
		delete stun;
	}
	proxy_cli = nullptr;

	LOGN("Flexisip %s-server exiting normally.", fName.c_str());
	if (trackAllocs) dump_remaining_msgs();
	GenericManager::get()->sendTrap("Flexisip " + fName + "-server exiting normally");

	bctbx_uninit_logger();
	return 0;
}
