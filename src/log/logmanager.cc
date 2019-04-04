/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include "flexisip-config.h"
#include "flexisip/logmanager.hh"


#include <syslog.h>



using namespace std;

static BctbxLogLevel flexisip_sysLevelMin = BCTBX_LOG_ERROR;

namespace flexisip {
	
static void syslogHandler(void *info, const char *domain, BctbxLogLevel log_level, const char *str, va_list l) {
	if (log_level >= flexisip_sysLevelMin) {
		int syslev = LOG_ALERT;
		switch (log_level) {
			case BCTBX_LOG_DEBUG:
			syslev = LOG_DEBUG;
			break;
			case BCTBX_LOG_MESSAGE:
			syslev = LOG_INFO;
			break;
			case BCTBX_LOG_WARNING:
			syslev = LOG_WARNING;
			break;
			case BCTBX_LOG_ERROR:
			syslev = LOG_ERR;
			break;
			case BCTBX_LOG_FATAL:
			syslev = LOG_ALERT;
			break;
			default:
			syslev = LOG_ERR;
		}
		vsyslog(syslev, str, l);
	}
}

LogManager & LogManager::get(){
	if (!sInstance) sInstance = new LogManager();
	return *sInstance;
}

BctbxLogLevel LogManager::logLevelFromName(const std::string & name) const{
	BctbxLogLevel log_level;
	if (level == "debug") {
		log_level = BCTBX_LOG_DEBUG;
	} else if (level == "message") {
		log_level = BCTBX_LOG_MESSAGE;
	} else if (level == "warning") {
		log_level = BCTBX_LOG_WARNING;
	} else if (level == "error") {
		log_level = BCTBX_LOG_ERROR;
	} else {
		LOGE("Invalid log level name '%s'", name.c_str());
		log_level = BCTBX_LOG_ERROR;
	}
	return log_level;
}

void LogManager::initialize(const Parameters& params){
	if (mInitialized){
		LOGE("LogManager already initialized.");
		return;
	}
	mInitialized = true;
	if (params.enableSyslog) {
		openlog("flexisip", 0, LOG_USER);
		setlogmask(~0);
		bctbx_log_handler_t *syshandler = bctbx_create_log_handler(syslogHandler, bctbx_logv_out_destroy, NULL);
		if (syshandler) bctbx_add_log_handler(syshandler);
		else ::syslog(LOG_ERR, "Could not create syslog handler");
		flexisip_sysLevelMin = params.syslogLevel;
	}
	if (flexisip_sysLevelMin < params.level) params.level = flexisip_sysLevelMin;
	bctbx_set_log_level(NULL /*any domain*/, params.level);
			
	ostringstream pathStream;
	pathStream << params.logDirectory << "/" << params.fileName;
	FILE *f = fopen(pathStream.str().c_str() , "a");
	if (f) {
		string msg = "Writing logs in : " + pathStream.str();
		if (params.enableSyslog) ::syslog(LOG_INFO, msg.c_str(), msg.size());
		else printf("%s\n", msg.c_str());
		
		bctbx_log_handler_t *handler = bctbx_create_file_log_handler(params.fileMaxSize, params.logDirectory.c_str(), params.fileName.c_str(), f);
		if (handler) bctbx_add_log_handler(handler);
		else if (params.enableSyslog) ::syslog(LOG_ERR, "Could not create log file handler.");
		else printf("ERROR : Could not create log file handler.\n");
	} else {
		string msg = "Could not open/create log file '" + pathStream.str() + "' : " + string(strerror(errno));
		if (params.enableSyslog) ::syslog(LOG_INFO, msg.c_str(), msg.size());
		else printf("%s\n", msg.c_str());
	}
	enableUserErrorsLogs(params.enableUserErrors);
	if (params.enableStdout) {
		bctbx_set_log_handler_for_domain(bctbx_logv_out, NULL);
	}
}

void LogManager::setLogLevel(BctbxLogLevel level){
	bctbx_set_log_level(NULL /*any domain*/, level);
}

void LogManager::setSyslogLevel(BctbxLogLevel level){
	flexisip_sysLevelMin = level;
}

void LogManager::enableUserErrorsLogs(bool val){
	bctbx_set_log_level(FLEXISIP_USER_ERRORS_LOG_DOMAIN, val ? BCTBX_LOG_WARNING : BCTBX_LOG_FATAL);
}

int LogManager::setContextualFilter(BctbxLogLevel level, const std::string &expression){
	shared_ptr<SipBooleanExpression> expr;
	if (!expression.empty()){
		try{
			expr = SipBooleanExpressionBuilder::get().parse(expression);
		}catch(...){
			return -1;
		}
	}
	mContextLevel = level;
	mMutex.lock();
	mCurrentFilter = expr;
	mMutex.unlock();
	return 0;
}

void LogManager::disable(){
	setLogLevel(BCTBX_LOG_FATAL);
}

void LogManager::setCurrentContext(const SipLogContext &ctx){
	shared_ptr<SipBooleanExpression> expr;
	mMutex.lock();
	expr = mCurrentFilter;
	mMutex.unlock();
	
	if (!expr) return; // Nothing to do.
	
	/* 
	 * Now evaluate the boolean expression to know whether logs should be output or not.
	 * If not, the default (normal) log level is used.
	 */
	if (expr->eval(*ctx->mMsgSip.getSip())){
		bctbx_set_thread_log_level(mContextLevel);
	}else{
		bctbx_set_thread_log_level(mLevel);
	}
}

void LogManager::clearCurrentContext(){
	bctbx_set_thread_log_level(mLevel);
}

SipLogContext::SipLogContext(const MsgSip & msg){
	LogManager::get().setCurrentContext(*this);
}

LogContext::~LogContext(){
	LogManager::get().clearCurrentContext();
}


}//end of namespace
