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
	FlexisipException();
	FlexisipException(string& message);
	FlexisipException(const char* message);
	virtual ~FlexisipException();
	//FlexisipException(FlexisipException&& other );
	FlexisipException(const FlexisipException& other );
	/**
	 * print stack strace to stderr
	 * */
	void printStackTrace() const;

	void printStackTrace(std::ostringstream & os) const;

	const char* what() const throw ();

private:
	string mMsg;
    void *mArray[20];
    size_t mSize;
    int mOffset; /*to hide last stack traces*/
};

inline   pumpstream&
operator<<( pumpstream&& __os, const FlexisipException& e)
{
	__os << e.what() << std::endl;
	e.printStackTrace(__os);
	return __os;
}

#endif /* FLEXISIPEXCEPTION_H_ */
