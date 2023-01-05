/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <algorithm>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <sofia-sip/su_md5.h>

#include <flexisip/common.hh>
#include <flexisip/configmanager.hh>
#include <flexisip/flexisip-version.h>
#include <flexisip/logmanager.hh>
#include <flexisip/sip-boolean-expressions.hh>

#include "configdumper.hh"
#include "lpconfig.h"

using namespace std;

namespace flexisip {

bool ConfigValueListener::sDirty = false;

bool ConfigValueListener::onConfigStateChanged(const ConfigValue& conf, ConfigState state) {
	switch (state) {
		case ConfigState::Commited:
			if (sDirty) {
				// Write to disk
				GenericStruct* rootStruct = GenericManager::get()->getRoot();
				ofstream cfgfile;
				cfgfile.open(GenericManager::get()->getConfigFile());
				FileConfigDumper dumper(rootStruct);
				dumper.setMode(FileConfigDumper::Mode::CurrentValue);
				cfgfile << dumper;
				cfgfile.close();
				LOGI("New configuration wrote to %s .", GenericManager::get()->getConfigFile().c_str());
				sDirty = false;
			}
			break;
		case ConfigState::Changed:
			sDirty = true;
			break;
		case ConfigState::Reset:
			sDirty = false;
			break;
		case ConfigState::Check:
			break;
	}
	return doOnConfigStateChanged(conf, state);
}

/*********************************************************************************************************************/
/* GenericEntry class                                                                                                */
/*********************************************************************************************************************/

void GenericEntry::DeprecationInfo::setAsDeprecaded(const std::string& date,
                                                    const std::string& version,
                                                    const std::string& text) {
	if (date.empty() || version.empty()) {
		throw std::invalid_argument(string(__func__) + "(): empty date or version");
	}
	mDate = date;
	mVersion = version;
	mText = text;
}

/**
 * Searches a string for a pattern, removes it, and sets the next chatacter to uppercase.
 * For instance, string a = "toto::titi"; camelFindAndReplace(a, "::"); would set a to "totoTiti"
 * @param haystack the string to convert to CamelCase
 * @param needle the string to remove from the haystack
 */
static void camelFindAndReplace(string& haystack, const string& needle) {
	size_t pos;
	while ((pos = haystack.find(needle)) != string::npos) {
		haystack.replace(pos, needle.length(), "");
		if (haystack.length() > pos) {
			stringstream ss;
			ss << char(toupper(haystack.at(pos)));
			haystack.replace(pos, 1, ss.str());
		}
	}
}

string GenericEntry::sanitize(const string& str) {
	string strnew = str;
	camelFindAndReplace(strnew, "::");
	camelFindAndReplace(strnew, "-");
	return strnew;
}

std::string GenericEntry::getCompleteName() const {
	if (mParent == nullptr) {
		return "";
	} else {
		string&& res = mParent->getCompleteName();
		if (!res.empty()) res += '/';
		res += mName;
		return move(res);
	}
}

string GenericEntry::getPrettyName() const {
	string pn(mName);
	char upper = char(toupper(::toupper(pn.at(0))));
	pn.erase(0, 1);
	pn.insert(0, 1, upper);
	size_t i = pn.find_first_of("::");
	if (string::npos != i) {
		pn.replace(i, 1, " ");
		pn.erase(i + 1, 1);
	}

	i = 0;
	while (string::npos != (i = pn.find_first_of('-', i))) {
		pn.replace(i, 1, " ");
	}
	return pn;
}

void GenericEntry::mibFragment(ostream& ost, string spacing) const {
	string s("OCTET STRING");
	doMibFragment(ost, "", "read-write", s, spacing);
}

void GenericEntry::doMibFragment(
    ostream& ostr, const string& def, const string& access, const string& syntax, const string& spacing) const {
	if (!getParent()) LOGA("no parent found for %s", getName().c_str());
	ostr << spacing << sanitize(getName()) << " OBJECT-TYPE" << endl
	     << spacing << "	SYNTAX"
	     << "	" << syntax << endl
	     << spacing << "	MAX-ACCESS	" << access << endl
	     << spacing << "	STATUS	current" << endl
	     << spacing << "	DESCRIPTION" << endl
	     << spacing << "	\"" << escapeDoubleQuotes(getHelp()) << endl
	     << spacing << "	"
	     << " Default:" << def << endl
	     << spacing << "	"
	     << " PN:" << getPrettyName() << "\"" << endl
	     << spacing << "	::= { " << sanitize(getParent()->getName()) << " " << mOid->getLeaf() << " }" << endl;
}

GenericEntry::GenericEntry(const string& name, GenericValueType type, const string& help, oid oid_index)
    : mName(name), mHelp(help), mType(type), mOidLeaf(oid_index) {
	mConfigListener = NULL;
	size_t idx;
	for (idx = 0; idx < name.size(); idx++) {
		if (name[idx] == '_')
			LOGA("Underscores not allowed in config items, please use minus sign (while checking generic entry name "
			     "'%s').",
			     name.c_str());
		if (type != Struct && isupper(name[idx])) {
			LOGA("Uppercase characters not allowed in config items, please use lowercase characters only (while "
			     "checking generic entry name '%s').",
			     name.c_str());
		}
	}

	if (oid_index == 0) {
		mOidLeaf = Oid::oidFromHashedString(name);
	}
}

std::string GenericEntry::escapeDoubleQuotes(const std::string& str) {
	string escapedStr = "";
	for (auto it = str.cbegin(); it != str.cend(); it++) {
		if (*it == '"') {
			escapedStr += "''";
		} else {
			escapedStr += *it;
		}
	}
	return escapedStr;
}

void GenericEntry::setParent(GenericEntry* parent) {
	mParent = parent;
	if (mOid) delete mOid;
	mOid = new Oid(parent->getOid(), mOidLeaf);

	string key = parent->getName() + "::" + mName;
	registerWithKey(key);
}

/*********************************************************************************************************************/

void ConfigValue::mibFragment(ostream& ost, string spacing) const {
	string s("OCTET STRING");
	doConfigMibFragment(ost, s, spacing);
}

void ConfigValue::doMibFragment(
    ostream& ostr, const string& def, const string& access, const string& syntax, const string& spacing) const {
	string config_access(mNotifPayload ? "accessible-for-notify" : mReadOnly ? "read-only" : "read-write");
	(void)def;
	(void)access;
	GenericEntry::doMibFragment(ostr, getDefault(), config_access, syntax, spacing);
}

void ConfigBoolean::mibFragment(ostream& ost, string spacing) const {
	string s("INTEGER { true(1),false(0) }");
	doConfigMibFragment(ost, s, spacing);
}
void ConfigInt::mibFragment(ostream& ost, string spacing) const {
	string s("Integer32");
	doConfigMibFragment(ost, s, spacing);
}
void StatCounter64::mibFragment(ostream& ost, string spacing) const {
	string s("Counter64");
	doMibFragment(ost, "", "read-only", s, spacing);
}
void GenericStruct::mibFragment(ostream& ost, string spacing) const {
	string parent = getParent() ? getParent()->getName() : "flexisipMIB";
	ost << spacing << sanitize(getName()) << "	"
	    << "OBJECT IDENTIFIER ::= { " << sanitize(parent) << " " << mOid->getLeaf() << " }" << endl;
}

void NotificationEntry::mibFragment(ostream& ost, string spacing) const {
	if (!getParent()) LOGA("no parent found for %s", getName().c_str());
	ost << spacing << sanitize(getName()) << " NOTIFICATION-TYPE" << endl
	    << spacing << "	OBJECTS	{	flNotifString	} " << endl
	    << spacing << "	STATUS	current" << endl
	    << spacing << "	DESCRIPTION" << endl
	    << spacing << "	\"" << escapeDoubleQuotes(getHelp()) << endl
	    << spacing << "	"
	    << " PN:" << getPrettyName() << "\"" << endl
	    << spacing << "	::= { " << sanitize(getParent()->getName()) << " " << mOid->getLeaf() << " }" << endl;
}

NotificationEntry::NotificationEntry(const std::string& name, const std::string& help, oid oid_index)
    : GenericEntry(name, Notification, help, oid_index), mInitialized(false) {
}

void NotificationEntry::setInitialized(bool status) {
	mInitialized = status;
	if (status) {
		const GenericEntry* source;
		string msg;
		if (!mPendingTraps.empty()) {
			LOGD("Sending %zd pending notifications", mPendingTraps.size());
		}
		while (!mPendingTraps.empty()) {
			tie(source, msg) = mPendingTraps.front();
			mPendingTraps.pop();
			send(source, msg);
		}
	}
}

void NotificationEntry::send(const string& msg) {
	send(NULL, msg);
}
void NotificationEntry::send(const GenericEntry* source, const string& msg) {
	LOGD("Sending trap %s: %s", source ? source->getName().c_str() : "", msg.c_str());

#ifdef ENABLE_SNMP
	if (!mInitialized) {
		mPendingTraps.push(make_tuple(source, msg));
		LOGD("Pending trap: SNMP not initialized");
		return;
	}

	static Oid& sMsgTemplateOid = GenericManager::get()->getRoot()->getDeep<GenericEntry>("notif/msg", true)->getOid();
	static Oid& sSourceTemplateOid =
	    GenericManager::get()->getRoot()->getDeep<GenericEntry>("notif/source", true)->getOid();

	/*
	 * See:
	 * http://net-snmp.sourceforge.net/dev/agent/notification_8c-example.html
	 * In the notification, we have to assign our notification OID to
	 * the snmpTrapOID.0 object. Here is it's definition.
	 */
	oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
	size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);

	netsnmp_variable_list* notification_vars = NULL;

	snmp_varlist_add_variable(&notification_vars, objid_snmptrap, objid_snmptrap_len, ASN_OBJECT_ID,
	                          (u_char*)mOid->mOidPath.data(), mOid->mOidPath.size() * sizeof(oid));

	snmp_varlist_add_variable(&notification_vars, (const oid*)sMsgTemplateOid.getValue().data(),
	                          sMsgTemplateOid.getValue().size(), ASN_OCTET_STR, (u_char*)msg.data(), msg.length());

	if (source) {
		string oidstr(source->getOidAsString());
		snmp_varlist_add_variable(&notification_vars, (const oid*)sSourceTemplateOid.getValue().data(),
		                          sSourceTemplateOid.getValue().size(), ASN_OCTET_STR, (u_char*)oidstr.data(),
		                          oidstr.length());
	}

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
#endif
}

/* ConfigValue */

ConfigValue::ConfigValue(
    const string& name, GenericValueType vt, const string& help, const string& default_value, oid oid_index)
    : GenericEntry(name, vt, help, oid_index), mValue(default_value), mDefaultValue(default_value) {
	mExportToConfigFile = true;
}

bool ConfigValue::invokeConfigStateChanged(ConfigState state) {
	if (getParent() && getParent()->getType() == Struct) {
		ConfigValueListener* listener = getParent()->getConfigListener();
		if (listener) {
			return listener->onConfigStateChanged(*this, state);
		} else {
			LOGE("%s doesn't implement a config change listener.", getParent()->getName().c_str());
		}
	}
	return true;
}

void ConfigValue::checkType(const string& value, bool isDefault) {
	if (getType() == Boolean) {
		if (value != "true" && value != "false" && value != "1" && value != "0") {
			ostringstream ostr;
			ostr << "invalid " << (isDefault ? "default" : "") << "value '" << value << "' for key '" << getName()
			     << "' in section '" << getParent()->getName() << "'";
			throw std::runtime_error(ostr.str());
		}
	}
}

void ConfigValue::set(const std::string& value) {
	checkType(value, false);
	mValue = value;
	mNextValue = mValue;
	mIsDefault = false;
}

void ConfigValue::restoreDefault() {
	mValue = mDefaultValue;
	mNextValue = mDefaultValue;
	mIsDefault = true;
}

void ConfigValue::setNextValue(const string& value) {
	checkType(value, false);
	mNextValue = value;
}

void ConfigValue::setDefault(const string& value) {
	checkType(value, true);
	mDefaultValue = value;
	if (mIsDefault) {
		mValue = mDefaultValue;
		mNextValue = mDefaultValue;
	}
}

const string& ConfigValue::get() const {
	if (mIsDefault && mFallback && !mFallback->isDefault()) {
		LOGW("'%s' isn't set but its old name is. Fallbacking on '%s'", getCompleteName().c_str(),
		     mFallback->getCompleteName().c_str());
		return mFallback->get();
	}
	return mValue;
}

const string& ConfigValue::getDefault() const {
	return mDefaultValue;
}

void ConfigValue::setFallback(const ConfigValue& fallbackValue) {
	mFallback = &fallbackValue;
}

/* Oid */

Oid::Oid(Oid& parent, oid leaf) {
	mOidPath = parent.getValue();
	mOidPath.push_back(leaf);
}

Oid::Oid(vector<oid> path, oid leaf) {
	mOidPath = path;
	mOidPath.push_back(leaf);
}

Oid::Oid(vector<oid> path) {
	mOidPath = path;
}

oid Oid::oidFromHashedString(const string& str) {
	su_md5_t md5[1];
	su_md5_init(md5);
	su_md5_update(md5, str.c_str(), str.size());
	uint8_t digest[SU_MD5_DIGEST_SIZE];
	su_md5_digest(md5, digest);
	oid oidValue = 0;
	for (int i = 0; i < 4; ++i) { // limit to half 32 bits [1]
		oidValue <<= 8;
		oidValue += digest[i];
	}
	return oidValue / 2; // takes only half the 32 bit size [1]
	                     // 1: snmpwalk cannot associate oid to name otherwise
}

void ConfigValue::setParent(GenericEntry* parent) {
	GenericEntry::setParent(parent);
#ifdef ENABLE_SNMP
	//	LOGD("SNMP registering %s %s (as %s)",mOid->getValueAsString().c_str(), mName.c_str(), sanitize(mName).c_str());
	netsnmp_handler_registration* reginfo =
	    netsnmp_create_handler_registration(sanitize(mName).c_str(), &GenericEntry::sHandleSnmpRequest,
	                                        (oid*)mOid->getValue().data(), mOid->getValue().size(), HANDLER_CAN_RWRITE);
	reginfo->my_reg_void = this;
	int res = netsnmp_register_scalar(reginfo);
	if (res != MIB_REGISTERED_OK) {
		if (res == MIB_DUPLICATE_REGISTRATION) {
			LOGE("Duplicate registration of SNMP %s", mName.c_str());
		} else {
			LOGE("Couldn't register SNMP %s", mName.c_str());
		}
	}
#endif
}

void StatCounter64::setParent(GenericEntry* parent) {
	GenericEntry::setParent(parent);

#ifdef ENABLE_SNMP
	//	LOGD("SNMP registering %s %s (as %s)",mOid->getValueAsString().c_str(), mName.c_str(), sanitize(mName).c_str());
	netsnmp_handler_registration* reginfo =
	    netsnmp_create_handler_registration(sanitize(mName).c_str(), &GenericEntry::sHandleSnmpRequest,
	                                        (oid*)mOid->getValue().data(), mOid->getValue().size(), HANDLER_CAN_RONLY);
	reginfo->my_reg_void = this;
	int res = netsnmp_register_read_only_scalar(reginfo);
	if (res != MIB_REGISTERED_OK) {
		if (res == MIB_DUPLICATE_REGISTRATION) {
			LOGE("Duplicate registration of SNMP %s", mName.c_str());
		} else {
			LOGE("Couldn't register SNMP %s", mName.c_str());
		}
	}
#endif
}

GenericStruct::GenericStruct(const string& name, const string& help, oid oid_index)
    : GenericEntry(name, Struct, help, oid_index) {
}

void GenericStruct::setParent(GenericEntry* parent) {
	GenericEntry::setParent(parent);
#ifdef ENABLE_SNMP
//	LOGD("SNMP node %s %s",mOid->getValueAsString().c_str(), mName.c_str());
#endif
}

void GenericStruct::deprecateChild(const char* name, const DeprecationInfo& info) {
	GenericEntry* e = find(name);
	if (e) e->setDeprecated(info);
}

void GenericStruct::addChildrenValues(ConfigItemDescriptor* items) {
	addChildrenValues(items, true);
}

void GenericStruct::addChildrenValues(ConfigItemDescriptor* items, bool hashed) {
	oid cOid = 1;

	for (; items->name != nullptr; items++) {
		unique_ptr<GenericEntry> val = nullptr;
		if (hashed) cOid = Oid::oidFromHashedString(items->name);
		if (!items->name) {
			LOGA("No name provided in configuration item");
		}
		if (!items->help) {
			LOGA("No help provided for configuration item '%s'", items->name);
		}
		if (!items->default_value) {
			LOGA("No default value provided for configuration item '%s'", items->name);
		}
		switch (items->type) {
			case Boolean:
				val = make_unique<ConfigBoolean>(items->name, items->help, items->default_value, cOid);
				break;
			case Integer:
				val = make_unique<ConfigInt>(items->name, items->help, items->default_value, cOid);
				break;
			case IntegerRange:
				val = make_unique<ConfigIntRange>(items->name, items->help, items->default_value, cOid);
				break;
			case String:
				val = make_unique<ConfigString>(items->name, items->help, items->default_value, cOid);
				break;
			case ByteSize:
				val = make_unique<ConfigByteSize>(items->name, items->help, items->default_value, cOid);
				break;
			case StringList:
				val = make_unique<ConfigStringList>(items->name, items->help, items->default_value, cOid);
				break;
			case BooleanExpr:
				val = make_unique<ConfigBooleanExpression>(items->name, items->help, items->default_value, cOid);
				break;
			default:
				LOGA("Bad ConfigValue type %u for %s!", items->type, items->name);
				break;
		}
		addChild(move(val));
		if (!hashed) ++cOid;
	}
}

StatCounter64* GenericStruct::createStat(const string& name, const string& help) {
	oid cOid = Oid::oidFromHashedString(name);
	auto val = make_unique<StatCounter64>(name, help, cOid);
	return addChild(move(val));
}
pair<StatCounter64*, StatCounter64*> GenericStruct::createStatPair(const string& name, const string& help) {
	return make_pair(createStat(name, help), createStat(name + "-finished", help + " Finished."));
}

unique_ptr<StatPair> GenericStruct::createStats(const string& name, const string& help) {
	auto start = createStat(name, help);
	auto finish = createStat(name + "-finished", help + " Finished.");
	return make_unique<StatPair>(start, finish);
}

struct matchEntryNameApprox {
	const string mName;
	matchEntryNameApprox(const char* name) : mName(name) {
	}
	bool operator()(const unique_ptr<GenericEntry>& e) {
		unsigned int i;
		int count = 0;
		int min_required = mName.size() - 2;
		if (min_required < 1) return false;

		for (i = 0; i < mName.size(); ++i) {
			if (e->getName().find(mName[i]) != string::npos) {
				count++;
			}
		}
		if (count >= min_required) {
			return true;
		}
		return false;
	}
};

GenericEntry* GenericStruct::findApproximate(const char* name) const {
	auto it = find_if(mEntries.begin(), mEntries.end(), matchEntryNameApprox(name));
	if (it != mEntries.end()) return it->get();
	return nullptr;
}

const list<unique_ptr<GenericEntry>>& GenericStruct::getChildren() const {
	return mEntries;
}

ConfigBoolean::ConfigBoolean(const string& name, const string& help, const string& default_value, oid oid_index)
    : ConfigValue(name, Boolean, help, default_value, oid_index) {
}

bool ConfigBoolean::parse(const string& value) {
	if (value == "true" || value == "1") return true;
	else if (value == "false" || value == "0") return false;
	throw FlexisipException("Bad boolean value '" + value + "'");
	return false;
}

bool ConfigBoolean::read() const {
	try {
		return parse(get());
	} catch (FlexisipException& e) {
		LOGA("%s", e.what());
	}
	return false;
}
bool ConfigBoolean::readNext() const {
	try {
		return parse(getNextValue());
	} catch (FlexisipException& e) {
		LOGA("%s", e.what());
	}
	return false;
}

void ConfigBoolean::write(bool value) {
	set(value ? "1" : "0");
}

ConfigInt::ConfigInt(const string& name, const string& help, const string& default_value, oid oid_index)
    : ConfigValue(name, Integer, help, default_value, oid_index) {
}

int ConfigInt::read() const {
	return atoi(get().c_str());
}
int ConfigInt::readNext() const {
	return atoi(getNextValue().c_str());
}
void ConfigInt::write(int value) {
	std::ostringstream oss;
	oss << value;
	set(oss.str());
}

ConfigIntRange::ConfigIntRange(const std::string& name,
                               const std::string& help,
                               const std::string& default_value,
                               oid oid_index)
    : ConfigValue(name, IntegerRange, help, default_value, oid_index) {
}

void ConfigIntRange::parse(const string& value) {
	std::string::size_type n = value.find('-');
	if (n == std::string::npos) {
		mMin = mMax = atoi(value.c_str());
	} else {
		mMin = atoi(value.substr(0, n).c_str());
		mMax = atoi(value.substr(n + 1).c_str());
	}
}

int ConfigIntRange::readMin() {
	try {
		parse(get());
		return mMin;
	} catch (const std::out_of_range& e) {
		LOGA("%s", e.what());
	}
	return -1;
}
int ConfigIntRange::readMax() {
	try {
		parse(get());
		return mMax;
	} catch (const std::out_of_range& e) {
		LOGA("%s", e.what());
	}
	return -1;
}
int ConfigIntRange::readNextMin() {
	try {
		parse(getNextValue());
		return mMin;
	} catch (const std::out_of_range& e) {
		LOGA("%s", e.what());
	}
	return -1;
}
int ConfigIntRange::readNextMax() {
	try {
		parse(getNextValue());
		return mMax;
	} catch (const std::out_of_range& e) {
		LOGA("%s", e.what());
	}
	return -1;
}

void ConfigIntRange::write(int min, int max) {
	if (min > max) {
		LOGA("ConfigIntRange: min is superior to max");
	} else {
		std::ostringstream oss;
		oss << min << "-" << max;
		set(oss.str());
	}
}

StatCounter64::StatCounter64(const string& name, const string& help, oid oid_index)
    : GenericEntry(name, Counter64, help, oid_index) {
	mValue = 0;
}

ConfigString::ConfigString(const string& name, const string& help, const string& default_value, oid oid_index)
    : ConfigValue(name, String, help, default_value, oid_index) {
}
ConfigString::~ConfigString() {
}

ConfigRuntimeError::ConfigRuntimeError(const string& name, const string& help, oid oid_index)
    : ConfigValue(name, RuntimeError, help, "", oid_index) {
	this->setReadOnly(true);
	this->mExportToConfigFile = false;
}

const string& ConfigString::read() const {
	return get();
}

ConfigByteSize::ConfigByteSize(const string& name, const string& help, const string& default_value, oid oid_index)
    : ConfigValue(name, String, help, default_value, oid_index) {
}
uint64_t ConfigByteSize::read() const {
	string str = get();
	if (str.find('K') != string::npos) {
		return stoll(str.substr(0, str.find('K'))) * 1000;
	}
	if (str.find('M') != string::npos) {
		return stoll(str.substr(0, str.find('M'))) * 1000000;
	}
	if (str.find('G') != string::npos) {
		return stoll(str.substr(0, str.find('G'))) * 1000000000;
	}
	return stoll(str);
}

void ConfigRuntimeError::writeErrors(GenericEntry* entry, ostringstream& oss) const {
	auto cs = dynamic_cast<GenericStruct*>(entry);
	if (cs) {
		const auto& children = cs->getChildren();
		for (auto it = children.begin(); it != children.end(); ++it) {
			writeErrors(it->get(), oss);
		}
	}

	if (!entry->getErrorMessage().empty()) {
		if (oss.tellp() > 0) oss << "|";
		oss << entry->getOidAsString() << ":" << entry->getErrorMessage();
	}
}

string ConfigRuntimeError::generateErrors() const {
	ostringstream oss;
	writeErrors(GenericManager::get()->getRoot(), oss);
	return oss.str();
}

ConfigStringList::ConfigStringList(const string& name, const string& help, const string& default_value, oid oid_index)
    : ConfigValue(name, StringList, help, default_value, oid_index) {
}

#define DELIMITERS " \n,"

list<string> ConfigStringList::parse(const std::string& in) {
	list<string> retlist;
	char* res = strdup(in.c_str());
	char* saveptr = NULL;
	char* ret = strtok_r(res, DELIMITERS, &saveptr);
	while (ret != NULL) {
		retlist.push_back(string(ret));
		ret = strtok_r(NULL, DELIMITERS, &saveptr);
	}
	free(res);
	return retlist;
}

list<string> ConfigStringList::read() const {
	return parse(get());
}

bool ConfigStringList::contains(const string& ref) const {
	auto l(read());
	return std::find(l.begin(), l.end(), ref) != l.end();
}

ConfigBooleanExpression::ConfigBooleanExpression(const string& name,
                                                 const string& help,
                                                 const string& default_value,
                                                 oid oid_index)
    : ConfigValue(name, BooleanExpr, help, default_value, oid_index) {
}

shared_ptr<SipBooleanExpression> ConfigBooleanExpression::read() const {
	return SipBooleanExpressionBuilder::get().parse(get());
}

std::unique_ptr<GenericManager> GenericManager::sInstance{};

static void init_flexisip_snmp() {
#ifdef ENABLE_SNMP
	int syslog = 0; /* change this if you want to use syslog */

	// snmp_set_do_debugging(1);
	/* print log errors to syslog or stderr */
	if (syslog) snmp_enable_calllog();
	else snmp_enable_stderrlog();

	/* make us a agentx client. */
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
	// netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,NETSNMP_DS_AGENT_X_SOCKET,"udp:localhost:161");
	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_VERBOSE, 0);

	/* initialize tcpip, if necessary */
	SOCK_STARTUP;

	/* initialize the agent library */
	int err = init_agent("flexisip");
	if (err != 0) {
		LOGA("error init snmp agent %d", errno);
	}
#endif
}

GenericManager* GenericManager::get() {
	if (sInstance == nullptr) {
		init_flexisip_snmp();
		// make_unique<>() cannot be used here because
		// the constructor of GenericManager is protected.
		sInstance.reset(new GenericManager{});
	}
	return sInstance.get();
}

RootConfigStruct::RootConfigStruct(const string& name, const string& help, vector<oid> oid_root_path)
    : GenericStruct(name, help, 1) {
	mOid = new Oid(oid_root_path, 1);
}
RootConfigStruct::~RootConfigStruct() {
}

#ifndef DEFAULT_LOG_DIR
#define DEFAULT_LOG_DIR "/var/opt/belledonne-communications/log/flexisip"
#endif

GenericManager::GenericManager()
    : mConfigRoot("flexisip",
                  "This is the default Flexisip (v" FLEXISIP_GIT_VERSION ") configuration file",
                  {1, 3, 6, 1, 4, 1, SNMP_COMPANY_OID}),
      mReader(&mConfigRoot) {
	// to make sure global_conf is instanciated first
	static ConfigItemDescriptor global_conf[] = {
	    // processus settings
	    {StringList, "default-servers",
	     "Servers started by default when no --server option is specified on command line. "
	     "Possible values are 'proxy', 'presence', 'conference', 'regevent' separated by whitespaces.",
	     "proxy"},
	    {Boolean, "auto-respawn",
	     "Automatically respawn flexisip in case of abnormal termination (crashes). This has an effect if "
	     "Flexisip has been launched with '--daemon' option only",
	     "true"},
	    {String, "plugins-dir", "Path to the directory where plugins can be found.", DEFAULT_PLUGINS_DIR},
	    {StringList, "plugins",
	     "Plugins to load. Look at <prefix>/lib/flexisip/plugins to know the list of installed plugin. The name of a "
	     "plugin can "
	     "be derivated from the according library name by striping out the extension part and the leading 'lib' "
	     "prefix.\n"
	     "E.g. putting 'jweauth' in this setting will make libjweauth.so library to be load on runtime.",
	     ""},
	    {Boolean, "dump-corefiles",
	     "Generate a core file on crash.\n"
	     "On GNU/Linux, the action to do on core dump is defined by the kernel file '/proc/sys/kernel/core_pattern'. "
	     "On recent distributions like RHEL 8, the generated cores is given by default to the core manager of SystemD "
	     "and the core can be easily listed by using coredumpctl(1) command.\n"
	     "On older distributions, the cores are often written in '/' directory. If your root directory has little "
	     "available space, it is recommended to relocate your core dumps in another place by modifying the "
	     "'core_pattern' file on system boot. This may be done by adding this line in '/etc/rc.local':\n"
	     "    echo '/home/cores/core.\%e.\%t.\%p' > /proc/sys/kernel/core_pattern\n"
	     "\n"
	     "See core(5) manual for more information about core handling on GNU/Linux.",
	     "false"},
	    {Boolean, "enable-snmp", "Enable SNMP.", "false"},

	    // log settings
	    {String, "log-directory",
	     "Directory where to create log files. Create logs are named as 'flexisip-<server_type>.log'. If "
	     "If several server types have been specified by '--server' option or 'global/default-servers' parameter, then "
	     "<server_type> is expanded "
	     "by a concatenation of all the server types joined with '+' character.\n"
	     "WARNING: Flexisip has no embedded log rotation system but provides a configuration file for logrotate. "
	     "Please ensure "
	     "that logrotate is installed and running on your system if you want to have Flexisip's logs rotated. Log "
	     "rotation can be customized by "
	     "editing /etc/logrotate.d/flexisip-logrotate.",
	     DEFAULT_LOG_DIR},
	    {String, "log-filename",
	     "Name of the log file. Any occurences of '{server}' will be replaced by the server type "
	     "which has been given by '--server' option or 'default-servers' parameter. If several server types have been "
	     "given, then '{server}' will be replaced by the concatenation of these separated by '+' character (e.g. "
	     "'proxy+presence')",
	     "flexisip-{server}.log"},
	    {String, "log-level", "Log file verbosity. Possible values are debug, message, warning and error", "error"},
	    {String, "syslog-level", "Syslog verbosity. Possible values are debug, message, warning and error", "error"},
	    {Boolean, "user-errors-logs",
	     "Log (on a different log domain) user errors like authentication, registration, routing, etc...", "false"},
	    {String, "contextual-log-filter",
	     "A boolean expression applied to current SIP message being processed. When matched, logs are output"
	     " provided that there level is greater than the value defined in contextual-log-level."
	     " The definition of the SIP boolean expression is the same as for entry filters of modules, which is "
	     "documented here: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Filter%20syntax/",
	     ""},
	    {String, "contextual-log-level",
	     "Verbosity of contextual logs to output when the condition defined in 'contextual-log-filter' is met.",
	     "debug"},
	    {String, "show-body-for",
	     "Filter expression applied to all messages, if true message body is shown, if false not. Can not be empty, "
	     "use 'true' or 'false' constants instead. The definition of the SIP boolean expression is documented here: "
	     "https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Filter%20syntax/\n"
	     "Example : content-type == 'application/sdp' && request.method == 'MESSAGE'",
	     "content-type == 'application/sdp'"},

	    // network settings
	    {StringList, "transports",
	     "List of white space separated SIP URIs where the proxy must listen.\n"
	     "Wildcard (*) can be used to mean 'all local ip addresses'. If 'transport' parameter is unspecified, it will "
	     "listen to both udp and tcp. A local address to bind onto can be indicated in the 'maddr' parameter, while "
	     "the domain part of the uris are used as public domain or ip address.\n"
	     "The 'sips' transport definitions accept two optional parameters:\n"
	     " - 'tls-certificates-dir' taking for value a path, with the same meaning as the 'tls-certificates-dir' "
	     "property of this section and overriding it for this given transport.\n"
	     " - 'tls-certificates-file' taking for value a file path, with the same meaning as the "
	     "'tls-certificates-file' "
	     "property of this section and overriding it for this given transport.\n"
	     " - 'tls-certificates-private-key' taking for value a file path, with the same meaning as the "
	     "'tls-certificates-private-key' "
	     "property of this section and overriding it for this given transport.\n"
	     " - 'tls-certificates-ca-file' taking for value a file path, with the same meaning as the "
	     "'tls-certificates-ca-file' "
	     "property of this section and overriding it for this given transport.\n"
	     " - 'tls-verify-incoming' taking for value '0' or '1', to indicate whether clients connecting are "
	     "required to present a valid client certificate. Default value is 0.\n"
	     " - 'tls-allow-missing-client-certificate' taking for value '0' or '1', to allow connections from clients "
	     "which have no certificate even if `tls-verify-incoming` has been enabled. That's useful if you wish to have "
	     "Flexisip to ask for a client certificate, but without failing if the client cannot provide one.\n"
	     " - 'tls-verify-outgoing' taking for value '0' or '1', whether flexisip should check the peer certificate"
	     " when it make an outgoing TLS connection to another server. Default value is 1.\n"
	     " - 'require-peer-certificate' (deprecated) same as tls-verify-incoming\n"
	     "\n"
	     "It is HIGHLY RECOMMENDED to specify a canonical name for 'sips' transport, so that the proxy can advertise "
	     "this information in Record-Route headers, which allows TLS cname check to be performed by clients.\n"
	     "Specifying a sip uri with transport=tls is not allowed: the 'sips' scheme must be used instead. As requested "
	     "by SIP RFC, IPv6 address must be enclosed within brakets.\n"
	     "Here are some examples to understand:\n"
	     " - listen on all local interfaces for udp and tcp, on standard port:\n"
	     "\ttransports=sip:*\n"
	     " - listen on all local interfaces for udp,tcp and tls, on standard ports:\n"
	     "\ttransports=sip:* sips:*\n"
	     " - listen only a specific IPv6 interface, on standard ports, with udp, tcp and tls\n"
	     "\ttransports=sip:[2a01:e34:edc3:4d0:7dac:4a4f:22b6:2083] sips:[2a01:e34:edc3:4d0:7dac:4a4f:22b6:2083]\n"
	     " - listen on tls localhost with 2 different ports and SSL certificates:\n"
	     "\ttransports=sips:localhost:5061;tls-certificates-dir=path_a "
	     "sips:localhost:5062;tls-certificates-dir=path_b\n"
	     " - listen on tls localhost with 2 peer certificate requirements:\n"
	     "\ttransports=sips:localhost:5061;tls-verify-incoming=0 sips:localhost:5062;tls-verify-incoming=1\n"
	     " - listen on 192.168.0.29:6060 with tls, but public hostname is 'sip.linphone.org' used in SIP messages. "
	     "Bind address won't appear in messages:\n"
	     "\ttransports=sips:sip.linphone.org:6060;maddr=192.168.0.29",
	     "sip:*"},
	    {StringList, "aliases",
	     "List of white space separated host names pointing to this machine. This is to prevent "
	     "loops while routing SIP messages.",
	     "localhost"},
	    {Integer, "idle-timeout", "Time interval in seconds after which inactive connections are closed.", "3600"},
	    {Integer, "keepalive-interval",
	     "Time interval in seconds for sending \"\\r\\n\\r\\n\" keepalives packets on inbound and outbound "
	     "connections. "
	     "A value of zero stands for no keepalive. The main purpose of sending keepalives is to keep connection alive "
	     "accross NATs, but it also"
	     " helps in detecting silently broken connections which can reduce the number socket descriptors used by "
	     "flexisip.",
	     "1800"},
	    {Integer, "proxy-to-proxy-keepalive-interval",
	     "Time interval in seconds for sending \"\\r\\n\\r\\n\" keepalives packets specifically for proxy "
	     "to proxy connections. Indeed, while it is undesirable to send frequent keepalives to mobile clients because "
	     "it drains their battery,"
	     " sending frequent keepalives has proven to be helpful to keep connections up between proxy nodes in a very "
	     "popular US virtualized datacenter."
	     " A value of zero stands for no keepalive.",
	     "0"},
	    {Integer, "transaction-timeout", "SIP transaction timeout in milliseconds. It is T1*64 (32000 ms) by default.",
	     "32000"},
	    {Integer, "udp-mtu",
	     "The UDP MTU. Flexisip will fallback to TCP when sending a message whose size exceeds the UDP MTU."
	     " Please read http://sofia-sip.sourceforge.net/refdocs/nta/nta__tag_8h.html#a6f51c1ff713ed4b285e95235c4cc999a "
	     "for more details. If sending large packets over UDP is not a problem, then set a big value such as 65535. "
	     "Unlike the recommandation of the RFC, the default value of UDP MTU is 1460 in Flexisip (instead of 1300).",
	     "1460"},
	    {StringList, "rtp-bind-address",
	     "You can specify the bind address for all RTP streams (MediaRelay and Transcoder). This parameter is only "
	     "useful for some specific networks, keeping the default value is recommended.",
	     "0.0.0.0 ::0"},

	    // TLS settings
	    {String, "tls-certificates-dir",
	     "Path to the directory where TLS server certificate and private key can be found,"
	     " concatenated inside an 'agent.pem' file. Any chain certificates must be put into a file named 'cafile.pem'. "
	     "The setup of agent.pem, and eventually cafile.pem is required for TLS transport to work.",
	     "/etc/flexisip/tls/"},
	    {String, "tls-certificates-file",
	     "Path to the file containing the server certificate chain. The file must be in PEM format, see OpenSSL"
	     "SSL_CTX_use_certificate_chain_file documentation. If used tls-certificates-private-key MUST be set.",
	     ""},
	    {String, "tls-certificates-private-key",
	     "Path to the file containing the private key. See OpenSSL SSL_CTX_use_PrivateKey_file documentation. If used "
	     "tls-certificates-file MUST be set.",
	     ""},
	    {String, "tls-certificates-ca-file",
	     "Path to the file contain CA certificates. See OpenSSL SSL_CTX_load_verify_locations and "
	     "SSL_CTX_set_client_CA_list documentation. Can be empty.",
	     ""},
	    {String, "tls-ciphers",
	     "Ciphers string to pass to OpenSSL in order to limit the cipher suites to use while establishing TLS sessions."
	     " Please take a look to ciphers(1) UNIX manual to get the list of keywords supported by your current version"
	     " of OpenSSL. You might visit https://www.openssl.org/docs/manmaster/man1/ciphers.html too. The default value"
	     " set by Flexisip should provide a high level of security while keeping an acceptable level of "
	     "interoperability"
	     " with currenttly deployed clients on the market.",
	     "HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL"},
	    {Boolean, "require-peer-certificate", "Ask for client certificate on TLS session establishing.", "false"},

	    // other settings
	    {String, "unique-id",
	     "Unique ID used to identify that instance of Flexisip. It must be a randomly generated "
	     "16-sized hexadecimal number. If empty, it will be randomly generated on each start of Flexisip.",
	     ""},
	    {Integer, "tport-message-queue-size",
	     "Number of SIP message that sofia can queue in a tport (a connection). It is 64 by default, hardcoded in "
	     "sofia-sip (sofia-sip also used to hardcode a max value, 1000). This is not sufficient for IM.",
	     "1000"},

	    // deprecated parameters
	    {ByteSize, "max-log-size",
	     "Max size of a log file before switching to a new log file, expressed with units. "
	     "For example: 10G, 100M. If -1 then there is no maximum size",
	     "-1"},
	    {Boolean, "use-maddr",
	     "Allow flexisip to use maddr in sips connections to verify the CN of the TLS "
	     "certificate.",
	     "false"},
	    {Boolean, "use-rfc2543-record-route",
	     "Allow Flexisip to use the deprecated param 'transport=tls' in record-route header.", "false"},

	    config_item_end};

	static ConfigItemDescriptor cluster_conf[] = {
	    {Boolean, "enabled",
	     "Enable cluster mode. If 'false', the parameters of [cluster] section won't have any "
	     "effect.",
	     "false"},
	    {String, "cluster-domain",
	     "Domain name that enables external SIP agents to access to the cluster. "
	     "Such domain is often associated to DNS SRV records for each proxy of the cluster, so that DNS resolution "
	     "returns the address of a specific proxy randomly.\n"
	     "Flexisip uses that domain when it needs to insert a 'Path' or 'Record-route' header addressing the "
	     "cluster instead of itself.",
	     ""},
	    {StringList, "nodes",
	     "List of IP addresses of all the proxies present in the cluster. SIP messages coming "
	     "from these addresses won't be challenged by the authentication module and won't have any rate limit "
	     "applied by the DoS protection module.",
	     ""},
	    {String, "internal-transport",
	     "Transport to use for communication with the other proxies of the cluster. "
	     "This is useful only when no transport declared in 'global/transport' parameter can be used to "
	     "reach the other proxies e.g. when inter-proxy communications are to be made through a private network.\n"
	     "Ex: sip:10.0.0.8:5059;transport=tcp",
	     ""},
	    config_item_end};

	static ConfigItemDescriptor mdns_conf[] = {
	    {Boolean, "enabled", "Set to 'true' to enable multicast DNS register", "false"},
	    {IntegerRange, "mdns-priority",
	     "Priority of this instance, lower value means more preferred.\n"
	     "'n': priority of n (example 10)\n"
	     "'n-m': random priority between n and m (example 10-50)",
	     "0"},
	    {Integer, "mdns-weight",
	     "A relative weight for Flexisips with the same priority, higher value means more preferred.\n"
	     "For example, if two Flexisips are registered on the same local domain with one at 20 and the other at 80"
	     ", then 20% of Flexisip traffic will be redirected to the first Flexisip and 80% to the other one.\n"
	     "The sum of all the weights of Flexisips on the same local domain must be 100.",
	     "100"},
	    {Integer, "mdns-ttl", "Time To Live of any mDNS query that will ask for this Flexisip instance", "3600"},
	    config_item_end};

	auto uNotifObjs = make_unique<GenericStruct>("notif", "Templates for notifications.", 1);
	uNotifObjs->setExportable(false);
	auto notifObjs = mConfigRoot.addChild(move(uNotifObjs));
	auto uNotifier = make_unique<NotificationEntry>("sender", "Send notifications", 1);
	mNotifier = notifObjs->addChild(move(uNotifier));
	auto nmsg = make_unique<ConfigString>("msg", "Notification message payload.", "", 10);
	nmsg->setNotifPayload(true);
	notifObjs->addChild(move(nmsg));
	auto nsoid = make_unique<ConfigString>("source", "Notification source payload.", "", 11);
	nsoid->setNotifPayload(true);
	notifObjs->addChild(move(nsoid));

	auto uGlobal = make_unique<GenericStruct>("global", "Some global settings of the flexisip proxy.", 2);
	auto global = mConfigRoot.addChild(move(uGlobal));
	global->addChildrenValues(global_conf);
	global->get<ConfigByteSize>("max-log-size")->setDeprecated({"2019-05-17", "2.0.0"});
	global->get<ConfigBoolean>("use-maddr")
	    ->setDeprecated({"2020-04-08", "2.0.0", "This parameter has no effect anymore."});
	global->get<ConfigString>("tls-certificates-dir")
	    ->setDeprecated({"2022-01-04", "2.2.0",
	                     "Prefer the new way of declaring TLS certificate with 'tls-certificates-file', "
	                     "'tls-certificates-private-key' and 'tls-certificates-ca-file'. "});
	global->get<ConfigBoolean>("use-rfc2543-record-route")
	    ->setDeprecated({"2022-12-01", "2.2.0",
	                     "Param 'transport=tls' is deprecated in rfc3261, you should now use 'sips:' scheme instead."});
	global->setConfigListener(this);

	auto version = make_unique<ConfigString>("version-number", "Flexisip version.", FLEXISIP_GIT_VERSION, 999);
	version->setReadOnly(true);
	version->setExportable(false);
	global->addChild(move(version));

	auto runtimeError = make_unique<ConfigRuntimeError>("runtime-error", "Retrieve current runtime error state.", 998);
	runtimeError->setExportable(false);
	runtimeError->setReadOnly(true);
	global->addChild(move(runtimeError));

	auto uCluster = make_unique<GenericStruct>(
	    "cluster",
	    "This section contains some parameters useful when the current proxy is part of a network of proxies (cluster) "
	    "which serve the same domain.",
	    0);
	auto cluster = mConfigRoot.addChild(move(uCluster));
	cluster->addChildrenValues(cluster_conf);
	cluster->setReadOnly(true);

	auto uMdns = make_unique<GenericStruct>(
	    "mdns-register", "Should the server be registered on a local domain, to be accessible via multicast DNS.", 0);
	auto mdns = mConfigRoot.addChild(move(uMdns));
	mdns->addChildrenValues(mdns_conf);
	mdns->setReadOnly(true);
}

bool GenericManager::doIsValidNextConfig(const ConfigValue& cv) {
	return true;
}

bool GenericManager::doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) {
	switch (state) {
		case ConfigState::Check:
			return doIsValidNextConfig(conf);
		case ConfigState::Changed:
			mDirtyConfig = true;
			break;
		case ConfigState::Reset:
			mDirtyConfig = false;
			break;
		case ConfigState::Commited:
			if (mDirtyConfig) {
				LOGI("Scheduling server restart to apply new config.");
				mDirtyConfig = false;
				mNeedRestart = true;
			}
			break;
	}
	return true;
}

int GenericManager::load(const std::string& configfile) {
	SLOGI << "Loading config file " << configfile;
	mConfigFile = configfile;
	int res = mReader.read(configfile);
	applyOverrides(false);
	return res;
}

void GenericManager::loadStrict() {
	mReader.reload();
	mReader.checkUnread();
	applyOverrides(true);
}

void GenericManager::applyOverrides(bool strict) {
	for (auto& it : mOverrides) {
		const std::string& key = it.first;
		const std::string& value = it.second;
		if (value.empty()) continue;
		ConfigValue* val = mConfigRoot.getDeep<ConfigValue>(key.c_str(), strict);
		if (val) val->set(value);
		else {
			SLOGUE << "Skipping config override " << key << ":" << value;
		}
	}
}

GenericStruct* GenericManager::getRoot() {
	return &mConfigRoot;
}

const GenericStruct* GenericManager::getGlobal() {
	return mConfigRoot.get<GenericStruct>("global");
}

int FileConfigReader::read(const std::string& filename) {
	int err;
	if (mCfg) {
		lp_config_destroy(mCfg);
	}
	mCfg = lp_config_new(NULL);
	mFilename = filename;
	err = lp_config_read_file(mCfg, filename.c_str());
	read2(mRoot, 0);
	return err;
}

int FileConfigReader::reload() {
	read2(mRoot, 0);
	return 0;
}

void FileConfigReader::onUnreadItem(void* p, const char* secname, const char* key, int lineno) {
	FileConfigReader* zis = (FileConfigReader*)p;
	zis->onUnreadItem(secname, key, lineno);
}

void FileConfigReader::onUnreadItem(const char* secname, const char* key, int lineno) {
	ostringstream ss;
	ss << "Unsupported parameter '" << key << "' in section [" << secname << "] at line " << lineno << ".";
	mHaveUnreads = true;
	GenericEntry* sec = mRoot->find(secname);
	if (sec == NULL) {
		sec = mRoot->findApproximate(secname);
		if (sec != NULL) {
			ss << " Unknown section '[" << secname << "]', did you mean '[" << sec->getName().c_str() << "]' instead?";
		} else {
			ss << " Unknown section '[" << secname << "]'.";
		}
	} else {
		GenericStruct* st = dynamic_cast<GenericStruct*>(sec);
		if (st) {
			GenericEntry* val = st->find(key);
			if (val == NULL) {
				val = st->findApproximate(key);
				if (val != NULL) {
					ss << " Did you mean '" << val->getName().c_str() << "'?";
				}
			}
		}
	}
	LOGEN("%s", ss.str().c_str());
}

void FileConfigReader::checkUnread() {
	lp_config_for_each_unread(mCfg, onUnreadItem, this);
	if (mHaveUnreads) LOGF("Some items or section are invalid in the configuration file. Please check it.");
}

int FileConfigReader::read2(GenericEntry* entry, int level) {
	auto cs = dynamic_cast<GenericStruct*>(entry);
	ConfigValue* cv;
	if (cs) {
		auto& children = cs->getChildren();
		for (auto& child : children) {
			read2(child.get(), level + 1);
		}
	} else if ((cv = dynamic_cast<ConfigValue*>(entry))) {
		if (level < 2) LOGF("ConfigValues at root is disallowed.");
		if (level > 2) LOGF("The current file format doesn't support recursive subsections.");

		const char* val =
		    lp_config_get_string(mCfg, cv->getParent()->getName().c_str(), cv->getName().c_str(), nullptr);
		if (val) {
			if (cv->isDeprecated()) {
				const auto& info = cv->getDeprecationInfo();
				SLOGW << "Deprecated parameter:\n"
				      << "\t[" << cv->getParent()->getName() << "/" << cv->getName() << "]\n"
				      << "\t" << info.getText() << "\n"
				      << "\tDeprecated since " << info.getDate() << " (Flexisip v" << info.getVersion() << ")\n";
			}
			try {
				cv->set(val);
			} catch (std::exception& e) {
				LOGF("While reading '%s', %s.", mFilename.c_str(), e.what());
			}
		} else {
			cv->restoreDefault();
		}
	}
	return 0;
}

FileConfigReader::~FileConfigReader() {
	if (mCfg) lp_config_destroy(mCfg);
}

GenericEntriesGetter* GenericEntriesGetter::sInstance = NULL;

#ifdef ENABLE_SNMP
int GenericEntry::sHandleSnmpRequest(netsnmp_mib_handler* handler,
                                     netsnmp_handler_registration* reginfo,
                                     netsnmp_agent_request_info* reqinfo,
                                     netsnmp_request_info* requests) {
	if (!reginfo->my_reg_void) {
		LOGE("no reg");
		return SNMP_ERR_GENERR;
	} else {
		GenericEntry* cv = static_cast<GenericEntry*>(reginfo->my_reg_void);
		return cv->handleSnmpRequest(handler, reginfo, reqinfo, requests);
	}
}

int ConfigRuntimeError::handleSnmpRequest(netsnmp_mib_handler* handler,
                                          netsnmp_handler_registration* reginfo,
                                          netsnmp_agent_request_info* reqinfo,
                                          netsnmp_request_info* requests) {
	if (reqinfo->mode != MODE_GET) return SNMP_ERR_GENERR;

	const string errors = generateErrors();
	//	LOGD("runtime error handleSnmpRequest %s -> %s", reginfo->handlerName, errors.c_str());
	return snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (const u_char*)errors.c_str(), errors.size());
}

int ConfigValue::handleSnmpRequest(netsnmp_mib_handler* handler,
                                   netsnmp_handler_registration* reginfo,
                                   netsnmp_agent_request_info* reqinfo,
                                   netsnmp_request_info* requests) {
	char* old_value;
	int ret;
	string newValue;

	switch (reqinfo->mode) {
		case MODE_GET:
			//		LOGD("str handleSnmpRequest %s -> %s", reginfo->handlerName, get().c_str());
			return snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (const u_char*)get().c_str(),
			                                get().size());
			break;
		case MODE_SET_RESERVE1:
			ret = netsnmp_check_vb_type(requests->requestvb, ASN_OCTET_STR);
			if (ret != SNMP_ERR_NOERROR) {
				netsnmp_set_request_error(reqinfo, requests, ret);
			}

			mNextValue.assign((char*)requests->requestvb->val.string, requests->requestvb->val_len);
			if (!invokeConfigStateChanged(ConfigState::Check)) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
			}
			break;
		case MODE_SET_RESERVE2:
			old_value = netsnmp_strdup_and_null((const u_char*)get().c_str(), get().size());
			if (!old_value) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
				return SNMP_ERR_NOERROR;
			}
			netsnmp_request_add_list_data(requests, netsnmp_create_data_list("old_value", old_value, free));
			break;
		case MODE_SET_ACTION:
			newValue.assign((char*)requests->requestvb->val.string, requests->requestvb->val_len);
			set(newValue);
			invokeConfigStateChanged(ConfigState::Changed);
			break;
		case MODE_SET_COMMIT:
			//		LOGD("str handleSnmpRequest %s <- %s", reginfo->handlerName, get().c_str());
			invokeConfigStateChanged(ConfigState::Commited);
			break;
		case MODE_SET_FREE:
			// Nothing to do
			break;
		case MODE_SET_UNDO:
			old_value = (char*)netsnmp_request_get_list_data(requests, "old_value");
			set(old_value);
			invokeConfigStateChanged(ConfigState::Reset);
			break;
		default:
			/* we should never get here, so this is a really bad error */
			snmp_log(LOG_ERR, "unknown mode (%d) in handleSnmpRequest\n", reqinfo->mode);
			return SNMP_ERR_GENERR;
	}
	return SNMP_ERR_NOERROR;
}

int ConfigBoolean::handleSnmpRequest(netsnmp_mib_handler* handler,
                                     netsnmp_handler_registration* reginfo,
                                     netsnmp_agent_request_info* reqinfo,
                                     netsnmp_request_info* requests) {
	int ret;
	u_short* old_value;
	switch (reqinfo->mode) {
		case MODE_GET:
			//		LOGD("bool handleSnmpRequest %s -> %d", reginfo->handlerName, read()?1:0);
			snmp_set_var_typed_integer(requests->requestvb, ASN_INTEGER, read() ? 1 : 0);
			break;
		case MODE_SET_RESERVE1:
			ret = netsnmp_check_vb_int_range(requests->requestvb, 0, 1);
			if (ret != SNMP_ERR_NOERROR) {
				netsnmp_set_request_error(reqinfo, requests, ret);
			}
			mNextValue = requests->requestvb->val.integer == 0 ? "0" : "1";
			if (!invokeConfigStateChanged(ConfigState::Check)) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
			}
			break;
		case MODE_SET_RESERVE2:
			old_value = (u_short*)malloc(sizeof(u_short));
			if (!old_value) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
				return SNMP_ERR_NOERROR;
			}
			*old_value = read() ? 1 : 0;
			netsnmp_request_add_list_data(requests, netsnmp_create_data_list("old_value", old_value, free));
			break;
		case MODE_SET_ACTION:
			write(*requests->requestvb->val.integer == 1);
			invokeConfigStateChanged(ConfigState::Changed);
			break;
		case MODE_SET_COMMIT:
			//		LOGD("bool handleSnmpRequest %s <- %d", reginfo->handlerName, read()?1:0);
			invokeConfigStateChanged(ConfigState::Commited);
			break;
		case MODE_SET_FREE:
			// Nothing to do
			break;
		case MODE_SET_UNDO:
			old_value = (u_short*)netsnmp_request_get_list_data(requests, "old_value");
			write(*old_value);
			invokeConfigStateChanged(ConfigState::Reset);
			break;
		default:
			/* we should never get here, so this is a really bad error */
			snmp_log(LOG_ERR, "unknown mode (%d)\n", reqinfo->mode);
			return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}

int ConfigInt::handleSnmpRequest(netsnmp_mib_handler* handler,
                                 netsnmp_handler_registration* reginfo,
                                 netsnmp_agent_request_info* reqinfo,
                                 netsnmp_request_info* requests) {
	int* old_value;
	int ret;
	std::ostringstream oss;

	switch (reqinfo->mode) {
		case MODE_GET:
			//		LOGD("int handleSnmpRequest %s -> %d", reginfo->handlerName, read());
			snmp_set_var_typed_integer(requests->requestvb, ASN_INTEGER, read());
			break;
		case MODE_SET_RESERVE1:
			ret = netsnmp_check_vb_type(requests->requestvb, ASN_INTEGER);
			if (ret != SNMP_ERR_NOERROR) {
				netsnmp_set_request_error(reqinfo, requests, ret);
			}
			oss << *requests->requestvb->val.integer;
			mNextValue = oss.str();
			if (!invokeConfigStateChanged(ConfigState::Check)) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
			}
			break;
		case MODE_SET_RESERVE2:
			old_value = (int*)malloc(sizeof(int));
			if (!old_value) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
				return SNMP_ERR_NOERROR;
			}
			*old_value = read();
			netsnmp_request_add_list_data(requests, netsnmp_create_data_list("old_value", old_value, free));
			break;
		case MODE_SET_ACTION:
			write(*requests->requestvb->val.integer);
			invokeConfigStateChanged(ConfigState::Changed);
			break;
		case MODE_SET_COMMIT:
			//		LOGD("int handleSnmpRequest %s <- %d", reginfo->handlerName, read());
			invokeConfigStateChanged(ConfigState::Commited);
			break;
		case MODE_SET_FREE:
			// Nothing to do
			break;
		case MODE_SET_UNDO:
			old_value = (int*)netsnmp_request_get_list_data(requests, "old_value");
			write(*old_value);
			invokeConfigStateChanged(ConfigState::Reset);
			break;
		default:
			/* we should never get here, so this is a really bad error */
			snmp_log(LOG_ERR, "unknown mode (%d)\n", reqinfo->mode);
			return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}

int StatCounter64::handleSnmpRequest(netsnmp_mib_handler* handler,
                                     netsnmp_handler_registration* reginfo,
                                     netsnmp_agent_request_info* reqinfo,
                                     netsnmp_request_info* requests) {
	//	LOGD("counter64 handleSnmpRequest %s -> %lu", reginfo->handlerName, read());

	switch (reqinfo->mode) {
		case MODE_GET:
			struct counter64 counter;
			counter.high = read() >> 32;
			counter.low = read() & 0x00000000FFFFFFFF;
			snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64, (const u_char*)&counter, sizeof(counter));
			break;
		default:
			/* we should never get here, so this is a really bad error */
			snmp_log(LOG_ERR, "unknown mode (%d)\n", reqinfo->mode);
			return SNMP_ERR_GENERR;
	}

	return SNMP_ERR_NOERROR;
}
#endif /* enable_snmp */

} // namespace flexisip
