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

#ifndef FLEXISIPEXCEPTION_H_
#define FLEXISIPEXCEPTION_H_

#include <exception>
#include <string>
#include <iostream>
#include <sstream>
#include <ostream>
#include "log/logmanager.hh"

using namespace std;

class FlexisipException: public exception {
public:

	FlexisipException();
	FlexisipException(string& message);
	FlexisipException(const char* message);
	virtual ~FlexisipException() throw ();
	FlexisipException(const FlexisipException& other );
	/**
	 * print stack strace to stderr
	 * */
	void printStackTrace() const;

	void printStackTrace(std::ostream & os) const;

	const char* what() throw ();
	const std::string str() const;
	
	/* same as osstringstream, but as osstream does not have cp contructor, FlexisipException can't inherit from osstream*/
	template<typename T2>  FlexisipException& operator<< (const T2& val){
		mOs << val;
		return *this;
	}
protected:
	int mOffset; /*to hide last stack traces*/
private:
    void *mArray[20];
    size_t mSize;
    string mWhat;
	ostringstream mOs;
};
std::ostream& operator<<(std::ostream& __os,const FlexisipException&  e);

#define FLEXISIP_EXCEPTION FlexisipException() << " " << __FILE__ << ":"<< __LINE__ << " "
#endif /* FLEXISIPEXCEPTION_H_ */
