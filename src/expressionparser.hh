/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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

#ifndef expressionparser_hh
#define expressionparser_hh

#include <string>
#include <memory>

class Arguments {
public:
	virtual ~Arguments(){};
	virtual std::string get(const std::string &arg) const =0;
	virtual bool isTrue(const std::string &arg) const =0;
};


class BooleanExpression{
protected:
	BooleanExpression(){};
public:
		virtual bool eval(const Arguments *args)=0;
		virtual ~BooleanExpression(){};
		static std::shared_ptr<BooleanExpression> parse(const std::string &str);
		std::string ptr();
};



#endif
