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
#include "flexisip-exception.hh"
#include <execinfo.h>
#include <unistd.h>


static void uncaught_handler () {
	std::exception_ptr p= current_exception();
	try {
		rethrow_exception(p);
	} catch (FlexisipException& e) {
		SLOGE << e ;
	} catch (std::exception& ee ) {
		SLOGE << "Unexpected exception ["<< ee.what() << " ] use FlexisipException for better debug";
	}
	abort();
}

FlexisipException e;


FlexisipException::FlexisipException(const char* message): mOffset(1), mSize(0){
	mSize = backtrace(mArray, sizeof(mArray)/sizeof(void*));
	if (message) mOs << message;
#if __clang
	if (get_terminate() != uncaught_handler)
#endif
	set_terminate(uncaught_handler); //invoke in case of uncautch exception for this thread
}

FlexisipException::FlexisipException(const FlexisipException& other ) : mOffset(other.mOffset), mSize(other.mSize) {
	memcpy(mArray,other.mArray,sizeof(mArray));
	mOs << other.str();
}

#if __cplusplus > 199711L
FlexisipException::FlexisipException(const string& msg): FlexisipException(msg.c_str()){
	mOffset++;
}
#else
FlexisipException::FlexisipException(const string& message): mOffset(1){
	mSize = backtrace(mArray, sizeof(mArray)/sizeof(void*));
	*this << message;
	set_terminate(uncaught_handler); //invoke in case of uncautch exception for this thread
}
#endif

FlexisipException::~FlexisipException() throw (){
	//nop
}


#if __cplusplus > 199711L
FlexisipException::FlexisipException(): FlexisipException(""){
	mOffset++;
}
#else
FlexisipException::FlexisipException(): mOffset(1){
	mSize = backtrace(mArray, sizeof(mArray)/sizeof(void*));
	*this << "";
	set_terminate(uncaught_handler); //invoke in case of uncautch exception for this thread
}
#endif

void FlexisipException::printStackTrace() const {
	backtrace_symbols_fd(mArray+mOffset, mSize-mOffset, STDERR_FILENO);
}

void FlexisipException::printStackTrace(std::ostream & os) const {
	char** bt = backtrace_symbols(mArray,mSize);
	for (unsigned  int i = mOffset; i < mSize; ++i) {
		os << bt[i] <<endl;
	}
	delete (bt);
}

const std::string &FlexisipException::str() const {
	mMessage = mOs.str(); //avoid returning a reference to temporary
	return mMessage;
}
const char* FlexisipException::what() const throw () {
	return str().c_str();
}


//Class Flexisip
std::ostream& operator<<(std::ostream& __os,const FlexisipException& e) {
	__os << e.str() << std::endl;
	e.printStackTrace(__os);
	return __os;
}
