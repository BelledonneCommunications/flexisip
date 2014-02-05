/*
 * FlexisipException.cpp
 *
 *  Created on: 4 févr. 2014
 *      Author: jehanmonnier
 */

#include <flexisip-exception.hh>
#include <execinfo.h>
#include <unistd.h>

FlexisipException::FlexisipException(const char* message): mOffset(2), mMsg(message){
	mSize = backtrace(mArray, sizeof(mArray)/sizeof(void*));
}
FlexisipException::FlexisipException(string& msg): FlexisipException(msg.c_str()){
	mOffset++;
}
FlexisipException::~FlexisipException() {
	//nop
}
FlexisipException::FlexisipException(): FlexisipException(""){
	mOffset++;
}
/*FlexisipException::FlexisipException(FlexisipException&& other) {
	FlexisipException(other);
}*/
FlexisipException::FlexisipException(const FlexisipException& other ) {
	mOffset=other.mOffset;
	memcpy(mArray,other.mArray,sizeof(mArray));
	mSize=other.mSize;
	mMsg=other.mMsg+other.str();
}
const char* FlexisipException::what() const throw (){
     return (mMsg+str()).c_str()  ;
}
 void FlexisipException::printStackTrace() const {

	 backtrace_symbols_fd(mArray+mOffset, mSize-mOffset, STDERR_FILENO);
 }

 void FlexisipException::printStackTrace(std::ostringstream & os) const {
 	 char** bt = backtrace_symbols(mArray,mSize);
 	 for (int i = mOffset; i < mSize; ++i) {
 		os << bt[i] <<endl;
 	  }
 	 delete (bt);
 }



