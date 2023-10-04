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

#include <cctype>
#include <regex>

#include <flexisip/flexisip-version.h>
#include <flexisip/module.hh>

#include "configdumper.hh"
#include "utils/string-utils.hh"

using namespace std;

namespace flexisip {

ostream& ConfigDumper::dump(ostream& ostr) const {
	return dump_recursive(ostr, mRoot, 0);
}

ostream& ConfigDumper::dump_recursive(std::ostream& ostr, const GenericEntry* entry, unsigned int level) const {
	const GenericStruct* cs = dynamic_cast<const GenericStruct*>(entry);
	const ConfigValue* value = dynamic_cast<const ConfigValue*>(entry);
	if (cs && shouldDumpModule(cs->getName()) && cs->isExportable()) {

		dumpModuleHead(ostr, cs, level);

		for (const auto& child : cs->getChildren()) {
			dump_recursive(ostr, child.get(), level + 1);
		}

		dumpModuleEnd(ostr, cs, level);

	} else if (value) {

		dumpModuleValue(ostr, value, level);
	}
	return ostr;
}

bool ConfigDumper::shouldDumpModule(const string& moduleName) const {
	smatch match;

	// When the dumpExperimental is activated, we should dump everything
	if (mDumpExperimental) return true;

	string name = moduleName;
	if (regex_match(moduleName, match, regex("module::([[:print:]]+)"))) {
		name = match[1].str();
	}

	auto registeredModuleInfo = ModuleInfoManager::get()->getRegisteredModuleInfo();
	auto it = find_if(registeredModuleInfo.cbegin(), registeredModuleInfo.cend(),
	                  [&name](const ModuleInfoBase* mi) { return mi->getModuleName() == name; });

	return (it != registeredModuleInfo.cend()) ? (*it)->getClass() == ModuleClass::Production : true;
}

/* FILE CONFIG DUMPER */

ostream& FileConfigDumper::printHelp(ostream& os, const string& help, const string& comment_prefix) const {
	auto it = help.cbegin();
	auto begin = it;
	bool lineStarts = true;
	bool isWithinBullet = false;
	bool isBulletFirstLine = false;

	for (; it != help.cend(); it++) {
		if (lineStarts) {
			string startOfLine = help.substr(it - help.cbegin(), 3);
			if (startOfLine == " - " || startOfLine == " * ") {
				// Beginning of a bullet
				isWithinBullet = true;
				isBulletFirstLine = true;
			} else {
				isWithinBullet = false;
			}
			lineStarts = false;
		}

		if (((it - begin) > 60 && *it == ' ') || *it == '\n') {
			os << comment_prefix;
			if (isWithinBullet && !isBulletFirstLine) os << "   "; // To make indentation.
			isBulletFirstLine = false;
			os << " " << string(begin, it) << endl;
			begin = it + 1;
		}
		if (*it == '\n') {
			lineStarts = true;
			isBulletFirstLine = false;
		}
	}
	os << comment_prefix << " ";
	if (isWithinBullet && !isBulletFirstLine) os << "   "; // To make indentation.
	os << string(begin, it) << endl;
	return os;
}

ostream&
FileConfigDumper::dumpModuleValue(std::ostream& ostr, const ConfigValue* val, [[maybe_unused]] int level) const {
	if (!val || !val->isExportable()) return ostr;
	if (!val->isDeprecated()) {

		printHelp(ostr, val->getHelp(), "#");
		ostr << "# Default: " << val->getDefault() << endl;

		if (!val->getDefaultUnit().empty()) {
			ostr << "# Default unit: " << val->getDefaultUnit() << endl;
		}

		if (mDumpMode == Mode::DefaultValue || (mDumpMode == Mode::DefaultIfUnset && val->isDefault())) {
			ostr << "#" << val->getName() << "=" << val->getDefault() << endl;
		} else {
			ostr << val->getName() << "=" << val->get() << endl;
		}
		ostr << endl;
	}
	return ostr;
}

ostream& FileConfigDumper::dumpModuleHead(std::ostream& ostr,
                                          const GenericStruct* moduleHead,
                                          [[maybe_unused]] int level) const {
	if (!moduleHead || !moduleHead->isExportable()) return ostr;

	if (moduleHead->getParent()) { // if moduleHead is not the root
		ostr << "\n\n\n\n\n" << flush;
	}

	ostr << "##" << endl;
	printHelp(ostr, moduleHead->getHelp(), "##");
	ostr << "##" << endl;
	if (moduleHead->getParent()) { // if moduleHead is not the root
		ostr << "[" << moduleHead->getName() << "]" << endl;
		ostr << endl;
	}

	return ostr;
}

/* TexFileConfigDumper */

string TexFileConfigDumper::escape(const string& strc) const {
	return StringUtils::transform(strc, {{'_', "\\_"}, {'<', "\\textless{}"}, {'>', "\\textgreater{}"}});
}

ostream&
TexFileConfigDumper::dumpModuleHead(std::ostream& ostr, const GenericStruct* cs, [[maybe_unused]] int level) const {
	if (cs->getParent()) {
		string pn = escape(cs->getPrettyName());
		ostr << "\\section{" << pn << "}" << endl << endl;
		ostr << "\\label{" << cs->getName() << "}" << endl;
		ostr << "\\subsection{Description}" << endl << endl;
		ostr << escape(cs->getHelp()) << endl << endl;
		ostr << "\\subsection{Parameters}" << endl << endl;
	}
	return ostr;
}

ostream&
TexFileConfigDumper::dumpModuleValue(std::ostream& ostr, const ConfigValue* val, [[maybe_unused]] int level) const {

	if (!val->isDeprecated()) {
		ostr << "\\subsubsection{" << escape(val->getName()) << "}" << endl;
		ostr << escape(val->getHelp()) << endl;
		ostr << "The default value is ``" << escape(val->getDefault()) << "''." << endl;
		ostr << endl;
	}
	return ostr;
}

/* Dokuwiki */

ostream&
DokuwikiConfigDumper::dumpModuleValue(std::ostream& ostr, const ConfigValue* val, [[maybe_unused]] int level) const {
	if (!val->isDeprecated()) {

		// dokuwiki handles line breaks with double backspaces
		auto help = StringUtils::transform(val->getHelp(), {{'\n', "\\\\ "}, {'`', "'' "}});
		StringUtils::searchAndReplace(help, ". ", ".\\\\ ");

		ostr << "|"
		     << "'''" << val->getName() << "'''"
		     << " | " << help << " | "
		     << "<code>" << val->getDefault() << "</code>"
		     << " | " << val->getTypeName() << " | " << endl;
	}
	return ostr;
}

ostream&
DokuwikiConfigDumper::dumpModuleHead(std::ostream& ostr, const GenericStruct* cs, [[maybe_unused]] int level) const {
	// we have a generic struc: we're on top level: get module name and description
	ostr << "====" << cs->getPrettyName() << "====" << endl;
	ostr << endl << cs->getHelp() << endl;
	ostr << endl << "Configuration options:" << endl;

	ostr << "^ Name ^ Description ^ Default value ^ Type ^" << endl;
	return ostr;
}

/* MediaWiki */

ostream&
MediaWikiConfigDumper::dumpModuleHead(std::ostream& ostr, const GenericStruct* cs, [[maybe_unused]] int level) const {
	// we have a generic struc: we're on top level: get module name and description
	ostr << "====" << cs->getPrettyName() << "====" << endl;
	ostr << endl << cs->getHelp() << endl;
	ostr << "----" << endl;
	ostr << endl << "Configuration options:" << endl;

	ostr << "{| border=\"1\" cellpadding=\"6\" style=\"border-collapse:collapse;\"" << endl;
	ostr << "!Name" << endl;
	ostr << "!Description" << endl;
	ostr << "!Default Value" << endl;
	ostr << "!Type" << endl;

	return ostr;
}

ostream&
MediaWikiConfigDumper::dumpModuleValue(std::ostream& ostr, const ConfigValue* val, [[maybe_unused]] int level) const {
	if (!val->isDeprecated()) {

		// MediaWiki handles line breaks with double backspaces
		auto help = StringUtils::transform(val->getHelp(), {{'\n', "<br/>"}, {'`', "'' "}});
		StringUtils::searchAndReplace(help, ". ", ".<br/> ");

		ostr << "|-" << endl // entry marker
		     << "|'''" << val->getName() << "'''" << endl
		     << "|" << help << endl
		     << "|"
		     << "<code>" << val->getDefault() << "</code>" << endl
		     << "|" << val->getTypeName() << endl;
	}
	return ostr;
}

ostream& MediaWikiConfigDumper::dumpModuleEnd(std::ostream& ostr,
                                              [[maybe_unused]] const GenericStruct* cs,
                                              [[maybe_unused]] int level) const {

	ostr << "|}" << endl;

	return ostr;
}

/* XWiki */

ostream&
XWikiConfigDumper::dumpModuleHead(std::ostream& ostr, const GenericStruct* cs, [[maybe_unused]] int level) const {
	// we have a generic struc: we're on top level: get module name and description
	ostr << "=" << cs->getPrettyName() << "=" << endl;
	ostr << endl << cs->getHelp() << endl;
	ostr << "----" << endl;
	ostr << endl << "Configuration options:" << endl;

	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Name";
	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Description";
	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Default Value";
	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Default Unit";
	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Type" << endl;

	return ostr;
}

ostream&
XWikiConfigDumper::dumpModuleValue(std::ostream& ostr, const ConfigValue* val, [[maybe_unused]] int level) const {
	if (!val->isDeprecated()) {
		ostr << "|=(% style=\"text-align: center;  vertical-align: middle; border: 1px solid #999\" %)"
		     << val->getName() << "|(% style=\"text-align: left; border: 1px solid #999\" %)((("
		     << escape(val->getHelp()) << ")))"
		     << "|(% style=\"text-align: center; vertical-align: middle; border: 1px solid #999\" %) ##"
		     << escape(val->getDefault()) << "##"
		     << "|(% style=\"text-align: center; vertical-align: middle; border: 1px solid #999\" %) ##"
		     << escape(string(val->getDefaultUnit())) << "##"
		     << "|(% style=\"text-align: center; vertical-align: middle; border: 1px solid #999\" %)"
		     << val->getTypeName() << endl;
	}
	return ostr;
}

std::string XWikiConfigDumper::escape(const std::string& str) {
	string escaped{};
	auto start = str.cbegin();
	decltype(start) end{};
	while ((end = find_if(start, str.cend(), [](const auto& c) { return ispunct(c); })) != str.cend()) {
		escaped.append(start, end);
		escaped += '~';
		escaped += *end++;
		start = end;
	}
	escaped.append(start, end);
	return escaped;
}

/* MIB */

ostream& MibDumper::dump(ostream& ostr) const {
	const time_t t = getCurrentTime();
	char mbstr[100];
	strftime(mbstr, sizeof(mbstr), "%Y%m%d0000Z", localtime(&t));

	ostr << "FLEXISIP-MIB DEFINITIONS ::= BEGIN" << endl
	     << "IMPORTS" << endl
	     << "	OBJECT-TYPE, Integer32, MODULE-IDENTITY, enterprises," << endl
	     << "	Counter64,NOTIFICATION-TYPE							  	FROM SNMPv2-SMI" << endl
	     << "	MODULE-COMPLIANCE, OBJECT-GROUP       					FROM SNMPv2-CONF;" << endl
	     << endl

	     << "flexisipMIB MODULE-IDENTITY" << endl
	     << "	LAST-UPDATED \"" << mbstr << "\"" << endl
	     << "	ORGANIZATION \"belledonne-communications\"" << endl
	     << "	CONTACT-INFO \"postal:   34 Avenue de L'europe 38 100 Grenoble France" << endl
	     << "		email:    contact@belledonne-communications.com\"" << endl
	     << "	DESCRIPTION  \"A Flexisip management tree.\"" << endl
	     << "	REVISION     \"" << mbstr << "\"" << endl
	     << "    DESCRIPTION  \"" FLEXISIP_GIT_VERSION << "\"" << endl
	     << "::={ enterprises " << SNMP_COMPANY_OID << " }" << endl
	     << endl;

	dump2(ostr, mRoot, 0);
	ostr << "END" << endl;
	return ostr;
}

ostream& MibDumper::dump2(ostream& ostr, GenericEntry* entry, int level) const {
	auto cs = dynamic_cast<GenericStruct*>(entry);
	ConfigValue* cVal;
	StatCounter64* sVal;
	NotificationEntry* ne;
	string spacing = "";
	while (level > 0) {
		spacing += "	";
		--level;
	}
	if (cs && shouldDumpModule(cs->getName())) {
		cs->mibFragment(ostr, spacing);
		for (auto it = cs->getChildren().begin(); it != cs->getChildren().end(); ++it) {
			if (!cs->isDeprecated()) {
				dump2(ostr, it->get(), level + 1);
				ostr << endl;
			}
		}
	} else if ((cVal = dynamic_cast<ConfigValue*>(entry)) != nullptr) {
		cVal->mibFragment(ostr, spacing);
	} else if ((sVal = dynamic_cast<StatCounter64*>(entry)) != nullptr) {
		sVal->mibFragment(ostr, spacing);
	} else if ((ne = dynamic_cast<NotificationEntry*>(entry)) != nullptr) {
		ne->mibFragment(ostr, spacing);
	}
	return ostr;
}

} // namespace flexisip
