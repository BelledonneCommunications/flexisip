#include <stdarg.h>
#include <stdio.h>

#include "common.hh"


int proxy_logLevel=PROXY_DEBUG|PROXY_INFO|PROXY_NOTICE|PROXY_WARN|PROXY_ERROR;

void default_loghandler(int log_level, const char *str, va_list l){
	const char *levname="";
	switch (log_level){
		case PROXY_DEBUG:
			levname="debug";
			break;
		case PROXY_ERROR:
			levname="error";
			break;
		case PROXY_WARN:
			levname="warn";
			break;
	}
	fprintf(stdout,"%s:",levname);
	vfprintf(stdout,str,l);
	fprintf(stdout,"\n");
}

LogHandler proxy_loghandler=default_loghandler;
