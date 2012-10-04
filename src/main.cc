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
#if defined(HAVE_CONFIG_H) && !defined(FLEXISIP_INCLUDED)
#include "flexisip-config.h"
#define FLEXISIP_INCLUDED
#endif
#include <syslog.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <iostream>

#include <mediastreamer2/mscommon.h>
#include "agent.hh"
#include "stun.hh"
#include "dos-protection.hh"

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


static int run=1;
static int pipe_fds[2]={-1}; //pipes used by flexisip to notify its starter process that everything went fine 
static pid_t flexisip_pid=0;
static su_root_t *root=NULL;
bool sUseSyslog=false;

using namespace ::std;

static void usage(const char *arg0){
	printf("%s\n"
	       "\t\t [--transports <transport uris (quoted)>]\n"
	       "\t\t [--debug]\n"
	       "\t\t [--daemon]\n"
	       "\t\t [--configfile <path>]\n"
	       "\t\t [--dump-default-config [node name]]\n"
	       "\t\t [--dump-snmp-mib]\n"
           "\t\t [--set <[node/]option[=value]>]\n"
	       "\t\t [--help]\n",arg0);
	exit(-1);
}

static void flexisip_stop(int signum){
	if (flexisip_pid>0){
		LOGD("Watchdog received quit signal...passing to child.");
		/*we are the watchdog, pass the signal to our child*/
		kill(flexisip_pid,signum);
	}else{
		LOGD("Received quit signal...");
		run=0;
		if (root){
			su_root_break (root);
		}
	}
}

static void flexisip_stat(int signum){
}

static void syslogHandler(OrtpLogLevel log_level, const char *str, va_list l){
	int syslev=LOG_ALERT;
	switch(log_level){
		case ORTP_DEBUG:
			syslev=LOG_DEBUG;
			break;
		case ORTP_MESSAGE:
			syslev=LOG_INFO;
			break;
/*			
		case ORTP_NOTICE:
			syslev=LOG_NOTICE;
			break;
*/
		 case ORTP_WARNING:
			syslev=LOG_WARNING;
			break;
		case ORTP_ERROR:
			syslev=LOG_ERR;
		case ORTP_FATAL:
			syslev=LOG_ALERT;
			break;
		default:
			syslev=LOG_ERR;
	}
	vsyslog(syslev,str,l);
}

static void defaultLogHandler(OrtpLogLevel log_level, const char *str, va_list l){
	const char *levname="none";
	switch(log_level){
		case ORTP_DEBUG:
			levname="D: ";
		break;
		case ORTP_MESSAGE:
			levname="M: ";
		break;
		case ORTP_WARNING:
			levname="W: ";
		break;
		case ORTP_ERROR:
			levname="E: ";
		break;
		case ORTP_FATAL:
			levname="F: ";
		break;
		default:
			break;
	}
	fprintf(stderr,"%s",levname);
	vfprintf(stderr,str,l);
	fprintf(stderr,"\n");
}

static void sofiaLogHandler(void *, char const *fmt, va_list ap){
	ortp_logv(ORTP_MESSAGE,fmt,ap);
}

static void timerfunc(su_root_magic_t *magic, su_timer_t *t, Agent *a){
	a->idle();
}

static void initialize(bool debug, bool useSyslog){
	sUseSyslog=useSyslog;
	if (useSyslog){
		openlog("flexisip", 0, LOG_USER);
		setlogmask(~0);
		ortp_set_log_handler(syslogHandler);
	}else{
		ortp_set_log_handler(defaultLogHandler);
	}
	ortp_init();
	ortp_set_log_file(stdout);
	ortp_set_log_level_mask(ORTP_DEBUG|ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
	
	if (debug==false){
		ortp_set_log_level_mask(ORTP_ERROR|ORTP_FATAL);
	}
	signal(SIGPIPE,SIG_IGN);
	signal(SIGTERM,flexisip_stop);
	signal(SIGINT,flexisip_stop);
	signal(SIGUSR1,flexisip_stat);
	/*enable core dumps*/
	struct rlimit lm;
	lm.rlim_cur=RLIM_INFINITY;
	lm.rlim_max=RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE,&lm)==-1){
		LOGE("Cannot enable core dump, setrlimit() failed: %s",strerror(errno));
	}
	
	su_init();
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
		unsigned int new_limit=getSystemFdLimit();
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

static void forkAndDetach(const char *pidfile, bool auto_respawn){
	int err=pipe(pipe_fds);
	if (err==-1){
		LOGE("Could not create pipes: %s",strerror(errno));
		exit(-1);
	}
	pid_t pid = fork();

	if (pid < 0){
		fprintf(stderr,"Could not fork: %s\n",strerror(errno));
		exit(-1);
	}

	if (pid==0){
		while(1){
			/*fork a second time for the flexisip real process*/
			flexisip_pid = fork();
			if (flexisip_pid < 0){
				fprintf(stderr,"Could not fork: %s\n",strerror(errno));
				exit(-1);
			}
			if (flexisip_pid > 0){
				/* We are in the watchdog process. It will block until flexisip exits cleanly.
				 In case of crash, it will restart it.*/
				#ifdef PR_SET_NAME
				if (prctl(PR_SET_NAME,"flexisip_wdog",NULL,NULL,NULL)==-1){
					LOGW("prctl() failed: %s",strerror(errno));
				}
				#endif
			do_wait:
			int status=0;
			pid_t retpid=wait(&status);
			if (retpid>0){
				if (WIFEXITED(status)) {
					if (WEXITSTATUS(status) == RESTART_EXIT_CODE) {
						LOGI("Flexisip restart to apply new config...");
					} else {
						LOGD("Flexisip exited normally");
						exit(0);
					}
				}else if (auto_respawn){
					LOGE("Flexisip apparently crashed, respawning now...");
					sleep(1);
					continue;
				}
			}else if (errno!=EINTR){
				LOGE("waitpid() error: %s",strerror(errno));
				exit(-1);
			}else goto do_wait;
			}else{
				/* This is the real flexisip process now.
				 * We can proceed with real start
				 */
#ifdef HAVE_SYS_PRCTL_H
				if (prctl(PR_SET_NAME,"flexisip",NULL,NULL,NULL)==-1){
					LOGW("prctl() failed: %s",strerror(errno));
				}
#endif
				/*we don't need the read pipe side*/
				close(pipe_fds[0]);
				makePidFile(pidfile);
				return;
			}
		}
		/*this is the case where we don't use the watch dog. Just create pid file and that's all.*/
		makePidFile(pidfile);
	}else{
		/* This is the initial process.
		 * It should block until flexisip has started sucessfully or rejected to start.
		 */
		uint8_t buf[4];
		// we don't need the write side of the pipe:
		close(pipe_fds[1]);
		err=read(pipe_fds[0],buf,sizeof(buf));
		if (err==-1 || err==0){
			LOGE("Flexisip failed to start.");
			exit(-1);
		}else{
			detach();
			exit(0);
		}
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
	const char *cfgfile=CONFIG_DIR "/flexisip.conf";
	bool debug=false;
	bool daemon=false;
	bool useSyslog=false;
	bool dump_default_cfg=false;
	char *dump_cfg_part=NULL;
	bool dump_snmp_mib=false;
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
			useSyslog=true;
			continue;
		}else if (strcmp(argv[i],"--debug")==0){
			debug=true;
			continue;
		}else if (strcmp(argv[i],"--configfile")==0 || strcmp(argv[i],"-c")==0){
			cfgfile=argv[i+1];
			i++;
			continue;
		}else if (strcmp(argv[i],"--dump-default-config")==0){
			dump_default_cfg=true;
			if ((i+1) < argc && argv[i+1][0]!='-') {
				i++;
				dump_cfg_part=argv[i];
			}
			continue;
		}else if (strcmp(argv[i],"--dump-snmp-mib")==0){
			dump_snmp_mib=true;
			i++;
			continue;
		}else if (strcmp(argv[i],"--set")==0){
			i++;
			const char* skey="";
			const char* svalue="";
			int shift=0;
			if (!parse_key_value(argc-i, &argv[i], &skey, &svalue, &shift)) {
				oset.insert(make_pair(skey,svalue));
				i +=shift;
			} else {
				fprintf(stderr,"Bad option --set %s\n",argv[i]);
			}
			continue;
		} else if (strcmp(argv[i],"--help")==0 || strcmp(argv[i],"-h")==0){
			// nothing
		} else {
			fprintf(stderr,"Bad option %s\n",argv[i]);
		}
		usage(argv[0]);
	}
	ortp_set_log_handler(defaultLogHandler);
	GenericManager *cfg=GenericManager::get();
	DosProtection *dos=DosProtection::get();

	if (dump_default_cfg){
		a=make_shared<Agent>(root);
		GenericStruct *rootStruct=GenericManager::get()->getRoot();
		if (dump_cfg_part && !(rootStruct=dynamic_cast<GenericStruct *>(rootStruct->find(dump_cfg_part)))) {
			cerr<<"Couldn't find node " << dump_cfg_part << endl;
			return -1;
		}
		if (oset.find("tex") != oset.end()) {
			cout<<TexFileConfigDumper(rootStruct);
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

	GenericManager::get()->setOverrideMap(oset);

	if (cfg->load(cfgfile)==-1){
		fprintf(stderr,"No configuration file found at %s.\nPlease specify a valid configuration file.\n"
		        "A default flexisip.conf.sample configuration file should be installed in " CONFIG_DIR "\n"
		        "Please edit it and restart flexisip when ready.\n"
		        "Alternatively a default configuration sample file can be generated at any time using --dump-default-config option.\n",cfgfile);
		return -1;
	}



	if (!debug) debug=cfg->getGlobal()->get<ConfigBoolean>("debug")->read();

	initialize (debug,useSyslog);

	log_boolean_expression_evaluation(oset.find("bee") != oset.end());
	log_boolean_expression_parsing(oset.find("bep") != oset.end());

	su_log_redirect(NULL,sofiaLogHandler,NULL);

	/*
	 NEVER NEVER create pthreads before this point : threads do not survive the fork below !!!!!!!!!!
	*/
	
	if (daemon){
		/*now that we have successfully loaded the config, there is nothing that can prevent us to start (normally).
		So we can detach.*/
		forkAndDetach(pidfile,cfg->getGlobal()->get<ConfigBoolean>("auto-respawn")->read());
	}

	LOGN("Starting flexisip version %s", VERSION);
	GenericManager::get()->sendTrap("Flexisip starting");
	root=su_root_create(NULL);
	a=make_shared<Agent>(root);
	a->start(transports);
#ifdef ENABLE_SNMP
	SnmpAgent lAgent(*a,*cfg, oset);
#endif
#ifdef ENABLE_TRANSCODER
	if (oset.find("notrans") == oset.end()) ms_init();
#endif
	a->loadConfig (cfg);

	increase_fd_limit();

	/* Install firewall rules to protect Flexisip for DOS attacks */
	dos->start();

	if (daemon){
		if (write(pipe_fds[1],"ok",3)==-1){
			LOGF("Failed to write starter pipe: %s",strerror(errno));
		}
	}
	
	if (cfg->getRoot()->get<GenericStruct>("stun-server")->get<ConfigBoolean>("enabled")->read()){
		stun=new StunServer(cfg->getRoot()->get<GenericStruct>("stun-server")->get<ConfigInt>("port")->read());
		stun->start();
	}


	su_timer_t *timer=su_timer_create(su_root_task(root),5000);
	su_timer_set_for_ever(timer,(su_timer_f)timerfunc,a.get()); 
	su_root_run(root);
	su_timer_destroy(timer);
	DosProtection::get()->stop();
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

