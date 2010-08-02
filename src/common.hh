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


#ifndef PROXY_COMMON_H
#define PROXY_COMMON_H

#include <cstdlib>
#include <cstdarg>

#define PROXY_DEBUG (1)
#define PROXY_INFO  (1<<1)
#define PROXY_NOTICE (1<<2)
#define PROXY_WARN  (1<<3)
#define PROXY_ERROR (1<<4)

extern int proxy_logLevel;

typedef void (*LogHandler)(int log_level, const char *str, va_list l);
extern LogHandler proxy_loghandler;

void default_log_handler(int log_level, const char *str, va_list l);

void SetLogLevel(int logmask);
void SetLogHandler(LogHandler handler);
	
static inline void LOGE(const char *str,...){
	if (proxy_logLevel & PROXY_ERROR){
		va_list l;
		va_start(l,str);
		proxy_loghandler(PROXY_ERROR,str,l);
		va_end(l);
	}
}

static inline void LOGW(const char *str,...){
	if (proxy_logLevel & PROXY_WARN){
		va_list l;
		va_start(l,str);
		proxy_loghandler(PROXY_WARN,str,l);
		va_end(l);
	}
}

static inline void LOGI(const char *str,...){
	if (proxy_logLevel & PROXY_INFO){
		va_list l;
		va_start(l,str);
		proxy_loghandler(PROXY_INFO,str,l);
		va_end(l);
	}
}

static inline void LOGN(const char *str,...){
	if (proxy_logLevel & PROXY_NOTICE){
		va_list l;
		va_start(l,str);
		proxy_loghandler(PROXY_NOTICE,str,l);
		va_end(l);
	}
}

static inline void LOGD(const char *str,...){
	if (proxy_logLevel & PROXY_DEBUG){
		va_list l;
		va_start(l,str);
		proxy_loghandler(PROXY_DEBUG,str,l);
		va_end(l);
	}
}

#endif
