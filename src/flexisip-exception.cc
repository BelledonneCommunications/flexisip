/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2014  Belledonne Communications SARL.
 
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


static void uncautch_handler () {
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

FlexisipException::FlexisipException(const char* message): mOffset(1){
	mSize = backtrace(mArray, sizeof(mArray)/sizeof(void*));
	if (message) *this << message;
#if __cplusplus > 199711L
	if (get_terminate() != uncautch_handler)
#endif
		set_terminate(uncautch_handler); //invoke in case of uncautch exception for this thread
}
#if __cplusplus > 199711L
FlexisipException::FlexisipException(string& msg): FlexisipException(msg.c_str()){
	mOffset++;
}
#else
FlexisipException::FlexisipException(string& message): mOffset(1){
	mSize = backtrace(mArray, sizeof(mArray)/sizeof(void*));
	*this << message;
	set_terminate(uncautch_handler); //invoke in case of uncautch exception for this thread
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
	set_terminate(uncautch_handler); //invoke in case of uncautch exception for this thread
}
#endif
/*FlexisipException::FlexisipException(FlexisipException&& other) {
	FlexisipException(other);
}*/
FlexisipException::FlexisipException(const FlexisipException& other ) {
	mOffset=other.mOffset;
	memcpy(mArray,other.mArray,sizeof(mArray));
	mSize=other.mSize;
	mOs << other.str();
	mWhat=other.mWhat;
}
const char* FlexisipException::what() throw (){
	mWhat=mOs.str();
	return mWhat.c_str();
}
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

const std::string FlexisipException::str() const {
	return mOs.str();
}
FlexisipException& FlexisipException::operator<< (const char *val) {
	mOs<<val;
	return *this;
}
FlexisipException& FlexisipException::operator<< (const string& val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(bool val){
	mOs<<val;
	return *this;
}


FlexisipException& FlexisipException::operator<<(short val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(unsigned short val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(int val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(unsigned int val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(long val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(unsigned long val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(long long val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(unsigned long long val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(float val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(double val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(long double val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(void* val){
	mOs<<val;
	return *this;
}

FlexisipException& FlexisipException::operator<<(streambuf* sb ){
	mOs<<sb;
	return *this;
}

FlexisipException& FlexisipException::operator<<(ostream& (*pf)(ostream&)){
	mOs<<pf;
	return *this;
}

FlexisipException& FlexisipException::operator<<(ios& (*pf)(ios&)){
	mOs<<pf;
	return *this;
}

FlexisipException& FlexisipException::operator<<(ios_base& (*pf)(ios_base&)){
	mOs<<pf;
	return *this;
}

std::ostream& operator<<(std::ostream& __os,const FlexisipException& e) {
	__os << e.str() << std::endl;
	e.printStackTrace(__os);
	return __os;
}


