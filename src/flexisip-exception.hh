/*
 * FlexisipException.h
 *
 *  Created on: 4 févr. 2014
 *      Author: jehanmonnier
 */

#ifndef FLEXISIPEXCEPTION_H_
#define FLEXISIPEXCEPTION_H_

#include <exception>
#include <string>
#include <iostream>
#include <sstream>
#include <ostream>
#include "log/logmanager.hh"

using namespace std;

class FlexisipException: public exception, public ostringstream {
public:
	explicit FlexisipException();
	explicit FlexisipException(string& message);
	explicit FlexisipException(const char* message);
	virtual ~FlexisipException();
	//FlexisipException(FlexisipException&& other );
	FlexisipException(const FlexisipException& other );
	/**
	 * print stack strace to stderr
	 * */
	void printStackTrace() const;

	void printStackTrace(std::ostringstream & os) const;

	const char* what() throw ();
protected:
	int mOffset; /*to hide last stack traces*/
private:
    void *mArray[20];
    size_t mSize;
    string mWhat;

//    friend pumpstream&  operator<<( pumpstream&& __os, const FlexisipException& e);
};

inline   pumpstream&
operator<<( pumpstream& __os, const FlexisipException& e)
{
	__os << e.str() << std::endl;
	e.printStackTrace(__os);
	return __os;
}

#define FLEXISIP_EXCEPTION FlexisipException() << " " << __FILE__ << ":"<< __LINE__ << " "
#endif /* FLEXISIPEXCEPTION_H_ */
