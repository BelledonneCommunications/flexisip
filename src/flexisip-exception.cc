/*
 * FlexisipException.cpp
 *
 *  Created on: 4 févr. 2014
 *      Author: jehanmonnier
 */

#include <flexisip-exception.hh>
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
	if (get_terminate() != uncautch_handler)
			set_terminate(uncautch_handler); //invoke in case of uncautch exception for this thread
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
	*static_cast<ostringstream*>(this) << other.str();
	mWhat=other.mWhat;
}
const char* FlexisipException::what() throw (){
	mWhat=str();
	return mWhat.c_str();
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



