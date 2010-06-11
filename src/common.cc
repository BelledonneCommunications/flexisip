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
	fflush(stdout);
}

LogHandler proxy_loghandler=default_loghandler;
