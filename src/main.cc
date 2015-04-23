/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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
#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif
#ifndef CONFIG_DIR
	#define CONFIG_DIR
#endif
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <iostream>

#ifdef ENABLE_TRANSCODER
#include <mediastreamer2/mscommon.h>
#endif

#include "agent.hh"
#include "stun.hh"

#include <cstdlib>
#include <cstdio>
#include <csignal>

#include "expressionparser.hh"

#include <sofia-sip/su_log.h>
#ifdef ENABLE_SNMP
#include "snmp-agent.h"
#endif
#ifndef VERSION
#define VERSION "DEVEL"
#endif //VERSION

#include "flexisip_gitversion.h"
#ifndef FLEXISIP_GIT_VERSION
#define FLEXISIP_GIT_VERSION "undefined"
#endif

#include "log/logmanager.hh"
#include <ortp/ortp.h>
#include <functional>
#include <list>

#include "etchosts.hh"

#include <fstream>

#ifdef ENABLE_PRESENCE
#include "presence/presence-server.h"
#endif //ENABLE_PRESENCE

#include "monitor.hh"

static int run=1;
static int pipe_wdog_flexisip[2]={-1}; // This is the pipe that flexisip will write to to signify it has started to the Watchdog
static pid_t flexisip_pid = -1;
static pid_t monitor_pid = -1;
static su_root_t *root=NULL;
bool sUseSyslog=false;

using namespace ::std;

static void usage(const char *arg0){
	printf("%s\n"
		"\t\t [--transports <transport uris (quoted)>]\n"
		"\t\t [--debug]\n"
		"\t\t [--daemon]\n"
		"\t\t [--configfile <path>]\n"
		"\t\t [--configover <path>]\n"
		"\t\t [--dump-default-config [node name]]\n"
		"\t\t [--dump-snmp-mib]\n"
		"\t\t [--set <[node/]option[=value]>]\n"
		"\t\t [--list-settables]\n"
		"\t\t [--list-modules]\n"
		"\t\t [--syslog]\n"
		"\t\t [--help]\n"
		"\t\t [--version]\n",
		arg0);
	exit(-1);
}

static void flexisip_stop(int signum){
	if (flexisip_pid>0){
		// We can't log from the parent process
		//LOGD("Watchdog received quit signal...passing to child.");
		/*we are the watchdog, pass the signal to our child*/
		kill(flexisip_pid,signum);
	}else{
		//LOGD("Received quit signal...");
		run=0;
		if (root){
			su_root_break (root);
		}
	}
}

static void flexisip_stat(int signum){
}

static void sofiaLogHandler(void *, const char *fmt, va_list ap){
	LOGDV(fmt,ap);
}

static void timerfunc(su_root_magic_t *magic, su_timer_t *t, Agent *a){
	a->idle();
}


static int getSystemFdLimit(){
	static int max_sys_fd=-1;
	if (max_sys_fd==-1){
#ifdef __linux
		char tmp[256]={0}; //make valgrind happy
		int fd=open("/proc/sys/fs/file-max",O_RDONLY);
		if (fd!=-1){
			if (read(fd,tmp,sizeof(tmp))>0){
				int val=0;
				if (sscanf(tmp,"%i",&val)==1){
					max_sys_fd=val;
					LOGI("System wide maximum number of file descriptors is %i",max_sys_fd);
				}
			}
			close(fd);
			fd=open("/proc/sys/fs/nr_open",O_RDONLY);
			if (fd!=-1){
				if (read(fd,tmp,sizeof(tmp))>0){
					int val=0;
					if (sscanf(tmp,"%i",&val)==1){
						LOGI("System wide maximum number open files is %i",val);
						if (val<max_sys_fd){
							max_sys_fd=val;
						}
					}
				}
				close(fd);
			}
		}
#else
	LOGW("Guessing of system wide fd limit is not implemented.");
	max_sys_fd=2048;
#endif
	}
	return max_sys_fd;
}

static void increase_fd_limit(void){
	struct rlimit lm;
	if (getrlimit(RLIMIT_NOFILE,&lm)==-1){
		LOGE("getrlimit(RLIMIT_NOFILE) failed: %s",strerror(errno));
	}else{
		unsigned new_limit=(unsigned)getSystemFdLimit();
		int old_lim=(int)lm.rlim_cur;
		LOGI("Maximum number of open file descriptors is %i, limit=%i, system wide limit=%i",
		     (int)lm.rlim_cur,(int)lm.rlim_max,getSystemFdLimit());

		if (lm.rlim_cur<new_limit){
			lm.rlim_cur=lm.rlim_max=new_limit;
			if (setrlimit(RLIMIT_NOFILE,&lm)==-1){
				LOGE("setrlimit(RLIMIT_NOFILE) failed: %s. Limit of number of file descriptors is low (%i).",strerror(errno),old_lim);
				LOGE("Flexisip will not be able to process a big number of calls.");
			}
			if (getrlimit(RLIMIT_NOFILE,&lm)==0){
				LOGI("Maximum number of file descriptor set to %i.",(int)lm.rlim_cur);
			}
		}
	}
}

/* Allows to detach the watdog from the PTY so that we don't get traces clobbering the terminal */
static void detach(){
	int fd;
	setsid();
	fd = open("/dev/null", O_RDWR);
	if (fd==-1){
		fprintf(stderr,"Could not open /dev/null\n");
		exit(-1);
	}
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	close(fd);
}

static void makePidFile(const char *pidfile){
	if (pidfile){
		FILE *f=fopen(pidfile,"w");
		fprintf(f,"%i",getpid());
		fclose(f);
	}
}

static void set_process_name(const char* process_name){
#ifdef PR_SET_NAME
		if (prctl(PR_SET_NAME,process_name,NULL,NULL,NULL)==-1){
			LOGW("prctl() failed: %s",strerror(errno));
		}
#endif
}

static void forkAndDetach(const char *pidfile, bool auto_respawn, bool startMonitor){
	int pipe_launcher_wdog[2];
	int err=pipe(pipe_launcher_wdog);
	bool launcherExited = false;
	if (err==-1){
		LOGE("Could not create pipes: %s",strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Creation of the watch-dog process */
	pid_t pid = fork();
	if (pid < 0){
		fprintf(stderr,"Could not fork: %s\n",strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (pid==0){
		/* We are in the watch-dog process */
		uint8_t buf[4];
		close(pipe_launcher_wdog[0]);
		set_process_name("flexisip_wdog");

		/* Creation of the flexisip process */
fork_flexisip:
		err = pipe(pipe_wdog_flexisip);
		if(err == -1) {
			LOGE("Could not create pipes: %s",strerror(errno));
			exit(EXIT_FAILURE);
		}
		flexisip_pid = fork();
		if (flexisip_pid < 0){
			fprintf(stderr,"Could not fork: %s\n",strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (flexisip_pid == 0) {

			/* This is the real flexisip process now.
			 * We can proceed with real start
			 */
			close(pipe_wdog_flexisip[0]);
			set_process_name("flexisip");
			makePidFile(pidfile);
			return;
		} else {
			LOGE("[WDOG] Flexisip PID: %d", flexisip_pid);
		}

		/*
		 * We are in the watch-dog process again
		 * Waiting for successfull initialisation of the flexisip process
		 */
		close(pipe_wdog_flexisip[1]);
		err=read(pipe_wdog_flexisip[0],buf,sizeof(buf));
		if (err==-1 || err==0){
			int errno_ = errno;
			LOGE("[WDOG] Read error from flexisip : %s", strerror(errno_));
			close(pipe_launcher_wdog[1]); // close launcher pipe to signify the error
			exit(EXIT_FAILURE);
		}
		close(pipe_wdog_flexisip[0]);

		/*
		 * Flexisip has successfully started.
		 * We can now start the Flexisip monitor if it is requierd
		 */
fork_monitor:
		if(startMonitor){
			int pipe_wd_mo[2];
			err = pipe(pipe_wd_mo);
			if(err == -1){
				LOGE("Cannot create pipe. %s", strerror(errno));
				kill(flexisip_pid, SIGTERM);
				exit(EXIT_FAILURE);
			}
			monitor_pid = fork();
			if (monitor_pid < 0){
				fprintf(stderr,"Could not fork: %s\n",strerror(errno));
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
			if(err == -1 || err == 0) {
				LOGE("[WDOG] Read error from Monitor process, killing flexisip");
				kill(flexisip_pid, SIGTERM);
				exit(EXIT_FAILURE);
			}
			close(pipe_wd_mo[0]);
		}

		/*
		 * We are in the watchdog process once again, and all went well, tell the launcher that it can exit
		 */

		if(!launcherExited && write(pipe_launcher_wdog[1], "ok", 3) == -1) {
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
		while(true) {
			int status=0;
			pid_t retpid=wait(&status);
			if (retpid>0){
				if(retpid == flexisip_pid) {
					if(startMonitor) kill(monitor_pid, SIGTERM);
					if (WIFEXITED(status)) {
						if (WEXITSTATUS(status) == RESTART_EXIT_CODE) {
							LOGI("Flexisip restart to apply new config...");
							sleep(1);
							goto fork_flexisip;
						} else {
							LOGD("Flexisip exited normally");
							exit(EXIT_SUCCESS);
						}
					}else if (auto_respawn){
						LOGE("Flexisip apparently crashed, respawning now...");
						sleep(1);
						goto fork_flexisip;
					}
				} else if(retpid == monitor_pid) {
					LOGE("The Flexisip monitor has crashed or has been illegally terminated. Restarting now");
					sleep(1);
					goto fork_monitor;
				}
			}else if (errno!=EINTR){
				LOGE("waitpid() error: %s",strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
	}else{
		/* This is the initial process.
		 * It should block until flexisip has started sucessfully or rejected to start.
		 */
		LOGE("[LAUNCHER] Watchdog PID: %d", pid);
		uint8_t buf[4];
		// we don't need the write side of the pipe:
		close(pipe_launcher_wdog[1]);

		// Wait for WDOG to tell us "ok" if all went well, or close the pipe if flexisip failed somehow
		err=read(pipe_launcher_wdog[0],buf,sizeof(buf));
		if (err==-1 || err==0){
			// pipe was closed, flexisip failed to start -> exit with failure
			LOGE("[LAUNCHER] Flexisip failed to start.");
			exit(EXIT_FAILURE);
		}else{
			// pipe written to, flexisip was OK
			LOGE("[LAUNCHER] Flexisip started correctly: exit");
			exit(EXIT_SUCCESS);
		}
	}
}

static void depthFirstSearch(string &path, GenericEntry *config, list<string> &allCompletions) {
	GenericStruct *gStruct=dynamic_cast<GenericStruct *>(config);
	if (gStruct) {
		string newpath;
		if (!path.empty()) newpath += path + "/" ;
		if (config->getName() != "flexisip") newpath += config->getName();
		    for (auto it=gStruct->getChildren().cbegin(); it != gStruct->getChildren().cend(); ++it) {
			    depthFirstSearch(newpath, *it, allCompletions);
		    }
		    return;
	}

	ConfigValue *cValue=dynamic_cast<ConfigValue *>(config);
	if (cValue) {
		string completion;
		if (!path.empty()) completion+= path + "/";
		completion += cValue->getName();
		allCompletions.push_back(completion);
	}
}

static int parse_key_value(int argc, char *argv[], const char **key, const char **value, int *shift) {
	int i=0;
	if (argc == 0 || argv[i][0]=='-') return -1;
	*key=argv[i];
	*shift=0;
	char *equal_sign=strchr(argv[i],'=');
	if (equal_sign) {
		*equal_sign='\0';
		*value=equal_sign+1;
		return 0;
	}

	++i;
	if (i < argc && argv[i][0]=='=') {
		++i;
		if (i>= argc || argv[i][0]=='-') return -1;
	}

	if (i < argc && argv[i][0]!='-') {
		*value=argv[i];
		*shift=i;
	}
	return 0;
}
int main(int argc, char *argv[]){
	shared_ptr<Agent> a;
	StunServer *stun=NULL;
	const char *transports=NULL;
	int i;
	const char *pidfile=NULL;
	const char *cfgfile = CONFIG_DIR "/flexisip.conf";
	bool debug=false;
	bool daemon=false;
	bool dump_default_cfg=false;
	char *dump_cfg_part=NULL;
	bool dump_snmp_mib=false;
	bool dump_settables=false;
	bool dump_modules=false;
	string settablesPrefix;
	string hostsOverride;
	string configOverride;
	map<string,string> oset;


	for(i=1;i<argc;++i){
		if (strcmp(argv[i],"--transports")==0){
			i++;
			if (i<argc){
				transports=argv[i];
				continue;
			}
		} else if (strcmp(argv[i],"--pidfile")==0){
			i++;
			if (i<argc){
				pidfile=argv[i];
				continue;
			}
		}else if (strcmp(argv[i],"--daemon")==0){
			daemon=true;
			continue;
		}else if (strcmp(argv[i],"--syslog")==0){
			sUseSyslog=true;
			continue;
		}else if (strcmp(argv[i],"--debug")==0){
			debug=true;
			continue;
		}else if (strcmp(argv[i],"--configfile")==0 || strcmp(argv[i],"-c")==0){
			cfgfile=argv[i+1];
			i++;
			continue;
		}else if (strcmp(argv[i],"--configover")==0 || strcmp(argv[i],"-co")==0){
			configOverride = argv[i+1];
			i++;
			continue;
		}else if (strcmp(argv[i],"--dump-default-config")==0){
			dump_default_cfg=true;
			if ((i+1) < argc && argv[i+1][0]!='-') {
				i++;
				dump_cfg_part=argv[i];
			}
			continue;
		} else if( strcmp(argv[i], "--list-modules")==0){
			dump_modules = true;
			i++;
			continue;
		}else if (strcmp(argv[i],"--dump-snmp-mib")==0){
			dump_snmp_mib=true;
			i++;
			continue;
		}else if (strcmp(argv[i],"--list-settables")==0){
			dump_settables=true;
			if ((i+1) < argc && argv[i+1][0]!='-') {
				i++;
				settablesPrefix=argv[i];
			}
			continue;
		}else if (strcmp(argv[i],"--set")==0){
			i++;
			const char* skey="";
			const char* svalue="";
			int shift=0;
			if (!parse_key_value(argc-i, &argv[i], &skey, &svalue, &shift)) {
				if (0 == strcmp(skey, "hosts")) hostsOverride = svalue;
				else oset.insert(make_pair(skey,svalue));
				i +=shift;
			} else {
				fprintf(stderr,"Bad option --set %s\n",argv[i]);
			}
			continue;
		} else if (strcmp(argv[i],"--help")==0 || strcmp(argv[i],"-h")==0){
			// nothing
		} else if (strcmp(argv[i],"--version")==0 || strcmp(argv[i],"-v")==0){
			fprintf(stdout,"%s (git: %s)\n",VERSION,FLEXISIP_GIT_VERSION);
			exit(0);
		}else {
			fprintf(stderr,"Bad option %s\n",argv[i]);
		}
		usage(argv[0]);
	}

	if (!configOverride.empty()) {
		ifstream overstr(configOverride.c_str(), ios_base::in);
		string line;
		while (getline(overstr, line)) {
			if (line.empty() || line[0] == '#') continue;
			size_t sep = line.find(" ");
			oset.insert(make_pair(line.substr(0, sep), line.substr(sep + 1)));
		}
	}

	if (!dump_default_cfg && !dump_snmp_mib && !dump_settables &&!dump_modules) {
		ortp_init();
		flexisip::log::preinit(sUseSyslog, debug);
	} else {
		flexisip::log::disableGlobally();
	}

	// Don't move these lines, it is black magic
	GenericManager *cfg=GenericManager::get();


	if (dump_default_cfg){
		a=make_shared<Agent>(root);
		GenericStruct *rootStruct=GenericManager::get()->getRoot();
		if (dump_cfg_part && !(rootStruct=dynamic_cast<GenericStruct *>(rootStruct->find(dump_cfg_part)))) {
			cerr<<"Couldn't find node " << dump_cfg_part << endl;
			return -1;
		}
		if (oset.find("tex") != oset.end()) {
			cout<<TexFileConfigDumper(rootStruct);
		} else if (oset.find("doku") != oset.end()) {
			cout << DokuwikiConfigDumper(rootStruct);
		} else {
			cout<<FileConfigDumper(rootStruct);
		}
		return 0;
	}

	if (dump_snmp_mib) {
		a=make_shared<Agent>(root);
		cout<<MibDumper(GenericManager::get()->getRoot());
		return 0;
	}
	if(dump_modules){
		a=make_shared<Agent>(root);
		GenericStruct* rootStruct = GenericManager::get()->getRoot();
		list<GenericEntry*> children = rootStruct->getChildren();
		for( auto it = children.begin(); it != children.end(); ++it ){
			GenericEntry* child = (*it);
			if( child->getName().find("module::") == 0 ){
				cout << child->getName() << endl;
			}
		}
		return 0;
	}

	if (dump_settables) {
		a=make_shared<Agent>(root);
		list<string> allCompletions;
		allCompletions.push_back("nosnmp");

		string empty;
		depthFirstSearch(empty, GenericManager::get()->getRoot(), allCompletions);

		for (auto it=allCompletions.cbegin(); it != allCompletions.cend(); ++it) {
			if (settablesPrefix.empty()) {
				cout << *it << "\n";
			} else if (0 == it->compare(0, settablesPrefix.length(), settablesPrefix)) {
				//cout << (it->c_str()+settablesPrefix.length()) << "\n";
				cout << *it << "\n";
			}
		}
		return 0;
	}




	GenericManager::get()->setOverrideMap(oset);

	if (cfg->load(cfgfile)==-1 && configOverride.empty()){
		fprintf(stderr,"No configuration file found at %s.\nPlease specify a valid configuration file.\n"
		        "A default flexisip.conf.sample configuration file should be installed in " CONFIG_DIR "\n"
		        "Please edit it and restart flexisip when ready.\n"
		        "Alternatively a default configuration sample file can be generated at any time using --dump-default-config option.\n",cfgfile);
		return -1;
	}



	if (!debug) debug=cfg->getGlobal()->get<ConfigBoolean>("debug")->read();

	bool dump_cores=cfg->getGlobal()->get<ConfigBoolean>("dump-corefiles")->read();


	// Initialize
	flexisip::log::initLogs(sUseSyslog, debug);
	flexisip::log::updateFilter(cfg->getGlobal()->get<ConfigString>("log-filter")->read());

	signal(SIGPIPE,SIG_IGN);
	signal(SIGTERM,flexisip_stop);
	signal(SIGINT,flexisip_stop);
	signal(SIGUSR1,flexisip_stat);

	if (dump_cores){
		/*enable core dumps*/
		struct rlimit lm;
		lm.rlim_cur=RLIM_INFINITY;
		lm.rlim_max=RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE,&lm)==-1){
			LOGE("Cannot enable core dump, setrlimit() failed: %s",strerror(errno));
		}
	}

	su_init();
	/*tell parser to support extra headers */
	sip_update_default_mclass(sip_extend_mclass(NULL));

	log_boolean_expression_evaluation(oset.find("bee") != oset.end());
	log_boolean_expression_parsing(oset.find("bep") != oset.end());
	if (!hostsOverride.empty()) {
		size_t pos = hostsOverride.find("=");
		EtcHostsResolver::get()->override(hostsOverride.substr(0, pos), hostsOverride.substr(pos+1));
	}

	su_log_redirect(NULL,sofiaLogHandler,NULL);

	/*
	 NEVER NEVER create pthreads before this point : threads do not survive the fork below !!!!!!!!!!
	*/
	bool monitorEnabled = cfg->getRoot()->get<GenericStruct>("monitor")->get<ConfigBoolean>("enabled")->read();
	if (daemon){
		/*now that we have successfully loaded the config, there is nothing that can prevent us to start (normally).
		So we can detach.*/
		bool autoRespawn = cfg->getGlobal()->get<ConfigBoolean>("auto-respawn")->read();
		forkAndDetach(pidfile, autoRespawn, monitorEnabled);
	}

	LOGN("Starting flexisip version %s (git %s)", VERSION, FLEXISIP_GIT_VERSION);
	GenericManager::get()->sendTrap("Flexisip starting");
	root=su_root_create(NULL);
	a=make_shared<Agent>(root);
	a->start(transports);
#ifdef ENABLE_SNMP
	SnmpAgent lAgent(*a,*cfg, oset);
#endif
#ifdef ENABLE_TRANSCODER
	if (oset.find("notrans") == oset.end()) {
		ms_init();
	}
#elif !defined(ENABLE_BOOST_LOG)
	ortp_init();
#endif

	if (!configOverride.empty()) cfg->applyOverrides(true); // using default + overrides

	a->loadConfig (cfg);

	// Create cached test accounts for the Flexisip monitor if necessary
	if(monitorEnabled) {
		try {
			Monitor::createAccounts();
		} catch(const FlexisipException &e) {
			LOGE("Could not create test accounts for the monitor. %s", e.str().c_str());
		}
	}

	increase_fd_limit();

	if (daemon){
		if (write(pipe_wdog_flexisip[1],"ok",3)==-1){
			LOGF("Failed to write starter pipe: %s",strerror(errno));
		}
		close(pipe_wdog_flexisip[1]);
	}

	if (cfg->getRoot()->get<GenericStruct>("stun-server")->get<ConfigBoolean>("enabled")->read()){
		stun=new StunServer(cfg->getRoot()->get<GenericStruct>("stun-server")->get<ConfigInt>("port")->read());
		stun->start();
	}

#ifdef ENABLE_PRESENCE
	flexisip::PresenceServer presenceServer(cfgfile);
	presenceServer.start();
#endif //ENABLE_PRESENCE


	su_timer_t *timer=su_timer_create(su_root_task(root),5000);
	su_timer_set_for_ever(timer,(su_timer_f)timerfunc,a.get());
	su_root_run(root);
	su_timer_destroy(timer);
	a.reset();
	if (stun) {
		stun->stop();
		delete stun;
	}
	su_root_destroy(root);
	LOGN("Flexisip exiting normally.");
	GenericManager::get()->sendTrap("Flexisip exiting normally");
	return 0;
}
