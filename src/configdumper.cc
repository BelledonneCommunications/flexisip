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

#include "configdumper.hh"
#include "module.hh"

using namespace std;

ostream &ConfigDumper::dump(ostream &ostr) const {
	return dump_recursive(ostr, mRoot, 0);
}

ostream &ConfigDumper::dump_recursive(std::ostream &ostr, const GenericEntry *entry, unsigned int level) const {
	const GenericStruct *cs = dynamic_cast<const GenericStruct *>(entry);
	const ConfigValue *value = dynamic_cast<const ConfigValue *>(entry);
	if (cs && shouldDumpModule(cs->getName()) && cs->isExportable()) {

		dumpModuleHead(ostr, cs, level);

		for (auto it = cs->getChildren().begin(); it != cs->getChildren().end(); ++it) {
			GenericEntry *child = *it;
			dump_recursive(ostr, child, level + 1);
		}

		dumpModuleEnd(ostr, cs, level);

	} else if (value) {

		dumpModuleValue(ostr, value, level);
	}
	return ostr;
}

struct matchModuleName {
	const std::string &mName;
	matchModuleName(const std::string &name) : mName(name) {
	}
	bool operator()(const ModuleInfoBase *mi) {
		return (mi->getModuleName() == mName);
	}
};

#define MODULE_PREFIX_LEN 8 /* strlen("module::") */
bool ConfigDumper::shouldDumpModule(const string &moduleName) const {
	// When the dumpExperimental is activated, we should dump everything
	if (mDumpExperimental)
		return true;

	string name = moduleName;
	if (name.find("module::") != name.npos) {
		name = moduleName.substr(MODULE_PREFIX_LEN);
	}
	auto registeredModuleInfo = ModuleFactory::get()->registeredModuleInfo();
	auto it = std::find_if(registeredModuleInfo.begin(), registeredModuleInfo.end(), matchModuleName(name));

	ModuleInfoBase *moduleInfo = (it != registeredModuleInfo.end()) ? *it : NULL;
	if (moduleInfo != NULL) {
		return moduleInfo->getClass() == ModuleClassProduction;
	} else {
		return true;
	}
}

/* FILE CONFIG DUMPER */

ostream &FileConfigDumper::printHelp(ostream &os, const string &help, const string &comment_prefix) const {
	const char *p = help.c_str();
	const char *begin = p;
	const char *origin = help.c_str();

	for (; *p != 0; ++p) {
		if ((p - begin > 60 && *p == ' ') || *p == '\n') {
			os << comment_prefix << " " << help.substr(begin - origin, p - begin) << endl;
			p++;
			begin = p;
		}
	}
	os << comment_prefix << " " << help.substr(begin - origin, p - origin) << endl;
	return os;
}

ostream &FileConfigDumper::dumpModuleValue(std::ostream &ostr, const ConfigValue *val, int level) const {
	if (!val || !val->isExportable())
		return ostr;
	if (!val->isDeprecated()) {

		printHelp(ostr, val->getHelp(), "#");
		ostr << "#  Default value: " << val->getDefault() << endl;

		if (mDumpDefault) {
			ostr << val->getName() << "=" << val->getDefault() << endl;
		} else {
			ostr << val->getName() << "=" << val->get() << endl;
		}
		ostr << endl;
	}
	return ostr;
}

ostream &FileConfigDumper::dumpModuleHead(std::ostream &ostr, const GenericStruct *moduleHead, int level) const {
	if (!moduleHead || !moduleHead->isExportable())
		return ostr;

	ostr << "##" << endl;

	printHelp(ostr, moduleHead->getHelp(), "##");

	ostr << "##" << endl;

	if (level > 0) {
		ostr << "[" << moduleHead->getName() << "]" << endl;
	} else
		ostr << endl;

	ostr << endl << endl << endl;

	return ostr;
}

/* TexFileComfigDumper */

static void escaper(string &str, char c, const string &replaced) {
	size_t i = 0;
	while (string::npos != (i = str.find_first_of(c, i))) {
		str.erase(i, 1);
		str.insert(i, replaced);
		i += replaced.length();
	}
}

static void string_escaper(string &str, const string &s, const string &replace) {
	size_t i = 0;
	while (string::npos != (i = str.find(s, i))) {
		str.erase(i, s.length());
		str.insert(i, replace);
		i += replace.length();
	}
}

string TexFileConfigDumper::escape(const string &strc) const {
	std::string str(strc);
	escaper(str, '_', "\\_");
	escaper(str, '<', "\\textless{}");
	escaper(str, '>', "\\textgreater{}");

	return str;
}

ostream &TexFileConfigDumper::dumpModuleHead(std::ostream &ostr, const GenericStruct *cs, int level) const {
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

ostream &TexFileConfigDumper::dumpModuleValue(std::ostream &ostr, const ConfigValue *val, int level) const {

	if (!val->isDeprecated()) {
		ostr << "\\subsubsection{" << escape(val->getName()) << "}" << endl;
		ostr << escape(val->getHelp()) << endl;
		ostr << "The default value is ``" << escape(val->getDefault()) << "''." << endl;
		ostr << endl;
	}
	return ostr;
}

/* Dokuwiki */

ostream &DokuwikiConfigDumper::dumpModuleValue(std::ostream &ostr, const ConfigValue *val, int level) const {
	if (!val->isDeprecated()) {

		// dokuwiki handles line breaks with double backspaces
		string help = val->getHelp();
		escaper(help, '\n', "\\\\ ");
		escaper(help, '`', "'' ");
		string_escaper(help, ". ", ".\\\\ ");

		ostr << "|"
			 << "'''" << val->getName() << "'''"
			 << " | " << help << " | "
			 << "<code>" << val->getDefault() << "</code>"
			 << " | " << val->getTypeName() << " | " << endl;
	}
	return ostr;
}

ostream &DokuwikiConfigDumper::dumpModuleHead(std::ostream &ostr, const GenericStruct *cs, int level) const {
	// we have a generic struc: we're on top level: get module name and description
	ostr << "====" << cs->getPrettyName() << "====" << endl;
	ostr << endl << cs->getHelp() << endl;
	ostr << endl << "Configuration options:" << endl;

	ostr << "^ Name ^ Description ^ Default value ^ Type ^" << endl;
	return ostr;
}

/* MediaWiki */

ostream &MediaWikiConfigDumper::dumpModuleHead(std::ostream &ostr, const GenericStruct *cs, int level) const {
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

ostream &MediaWikiConfigDumper::dumpModuleValue(std::ostream &ostr, const ConfigValue *val, int level) const {
	if (!val->isDeprecated()) {

		// MediaWiki handles line breaks with double backspaces
		string help = val->getHelp();
		escaper(help, '\n', "<br/> ");
		escaper(help, '`', "'' ");
		string_escaper(help, ". ", ".<br/> ");

		ostr << "|-" << endl // entry marker
			 << "|'''" << val->getName() << "'''" << endl
			 << "|" << help << endl
			 << "|"
			 << "<code>" << val->getDefault() << "</code>" << endl
			 << "|" << val->getTypeName() << endl;
	}
	return ostr;
}

ostream &MediaWikiConfigDumper::dumpModuleEnd(std::ostream &ostr, const GenericStruct *cs, int level) const {

	ostr << "|}" << endl;

	return ostr;
}


ostream &XWikiConfigDumper::dumpModuleHead(std::ostream &ostr, const GenericStruct *cs, int level) const {
	// we have a generic struc: we're on top level: get module name and description
	ostr << "=" << cs->getPrettyName() << "=" << endl;
	ostr << endl << cs->getHelp() << endl;
	ostr << "----" << endl;
	ostr << endl << "Configuration options:" << endl;

	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Name";
	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Description" ;
	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Default Value" ;
	ostr << "|=(% style=\"text-align: center; border: 1px solid #999\" %)Type" << endl;

	return ostr;
}

ostream &XWikiConfigDumper::dumpModuleValue(std::ostream &ostr, const ConfigValue *val, int level) const {
	if (!val->isDeprecated()) {

		// XWiki handles line breaks with double backspaces
		string help = val->getHelp();
		escaper(help, '\n', "\n ");
		escaper(help, '`', "'' ");

		ostr << "|=(% style=\"text-align: center;  vertical-align: middle; border: 1px solid #999\" %)" << val->getName() 
			 << "|(% style=\"text-align: left; border: 1px solid #999\" %)" << help 
			 << "|(% style=\"text-align: center; vertical-align: middle; border: 1px solid #999\" %) ##" << val->getDefault() << "##" 
			 << "|(% style=\"text-align: center; vertical-align: middle; border: 1px solid #999\" %)" << val->getTypeName() << endl;
	}
	return ostr;
}




/* MIB */

ostream &MibDumper::dump(ostream &ostr) const {
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
		 << "    DESCRIPTION  \"" PACKAGE_VERSION << "\"" << endl
		 << "::={ enterprises " << company_id << " }" << endl
		 << endl;

	dump2(ostr, mRoot, 0);
	ostr << "END" << endl;
	return ostr;
}

ostream &MibDumper::dump2(ostream &ostr, GenericEntry *entry, int level) const {
	GenericStruct *cs = dynamic_cast<GenericStruct *>(entry);
	ConfigValue *cVal;
	StatCounter64 *sVal;
	NotificationEntry *ne;
	string spacing = "";
	while (level > 0) {
		spacing += "	";
		--level;
	}
	if (cs && shouldDumpModule(cs->getName())) {
		cs->mibFragment(ostr, spacing);
		for (auto it = cs->getChildren().begin(); it != cs->getChildren().end(); ++it) {
			if (!cs->isDeprecated()) {
				dump2(ostr, *it, level + 1);
				ostr << endl;
			}
		}
	} else if ((cVal = dynamic_cast<ConfigValue *>(entry)) != NULL) {
		cVal->mibFragment(ostr, spacing);
	} else if ((sVal = dynamic_cast<StatCounter64 *>(entry)) != NULL) {
		sVal->mibFragment(ostr, spacing);
	} else if ((ne = dynamic_cast<NotificationEntry *>(entry)) != NULL) {
		ne->mibFragment(ostr, spacing);
	}
	return ostr;
}
