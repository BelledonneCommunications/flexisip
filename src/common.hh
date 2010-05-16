#ifndef PROXY_COMMON_H
#define PROXY_COMMON_H

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
