/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/configmanager.hh>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>

#include <sofia-sip/su_md5.h>

#include <flexisip/flexisip-version.h>
#include <flexisip/logmanager.hh>
#include <flexisip/sip-boolean-expressions.hh>

#include "agent.hh"
#include "configdumper.hh"
#include "exceptions/bad-configuration.hh"
#include "lpconfig.h"

using namespace std;

namespace flexisip {

namespace {
const RootConfigStruct* retrieveRoot(const GenericEntry* firstEntry) {
	const auto* entry = firstEntry;
	while (entry->getParent()) {
		entry = entry->getParent();
	}
	return dynamic_cast<const RootConfigStruct*>(entry);
}

RootConfigStruct* retrieveRoot(GenericEntry* firstEntry) {
	const auto* entry = firstEntry;
	return const_cast<RootConfigStruct*>(retrieveRoot(entry));
}
} // namespace

/*********************************************************************************************************************/
/* GenericEntry class */
/*********************************************************************************************************************/

bool GenericEntry::onConfigStateChanged(const ConfigValue& conf, ConfigState state) {
	// Get first available listener
	if (mConfigListener == nullptr) {
		if (getParent() == nullptr) {
			LOGE << conf.getName() << " does not implement a config change listener";
			return false;
		}
		return getParent()->onConfigStateChanged(conf, state);
	}

	auto* rootStruct = retrieveRoot(this);
	if (rootStruct == nullptr) return false; // should not happen

	switch (state) {
		case ConfigState::Committed:
			if (!rootStruct->hasCommittedChange()) {
				// Write to disk
				const auto& configFile = rootStruct->getConfigFile();
				ofstream cfgfile;
				cfgfile.open(configFile);
				FileConfigDumper dumper(rootStruct);
				dumper.setMode(FileConfigDumper::Mode::CurrentValue);
				cfgfile << dumper;
				cfgfile.close();
				LOGI << "New configuration wrote to " << configFile;
				rootStruct->setCommittedChange(true);
			}
			break;
		case ConfigState::Changed:
			rootStruct->setCommittedChange(false);
			break;
		case ConfigState::Reset:
			rootStruct->setCommittedChange(true);
			break;
		case ConfigState::Check:
			break;
	}
	return mConfigListener->doOnConfigStateChanged(conf, state);
}

void GenericEntry::DeprecationInfo::setAsDeprecated(const std::string& date,
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
 * Searches a string for a pattern, removes it, and sets the next character to uppercase.
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
		return std::move(res);
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

void GenericEntry::mibFragment(ostream& ost, const string& spacing) const {
	string s("OCTET STRING");
	doMibFragment(ost, "", "read-write", s, spacing);
}

void GenericEntry::doMibFragment(
    ostream& ostr, const string& def, const string& access, const string& syntax, const string& spacing) const {
	if (!getParent()) throw BadConfiguration{"no parent found for " + getName()};
	ostr << spacing << sanitize(getName()) << " OBJECT-TYPE" << endl
	     << spacing << "	SYNTAX" << "	" << syntax << endl
	     << spacing << "	MAX-ACCESS	" << access << endl
	     << spacing << "	STATUS	current" << endl
	     << spacing << "	DESCRIPTION" << endl
	     << spacing << "	\"" << escapeDoubleQuotes(getHelp()) << endl
	     << spacing << "	" << " Default:" << def << endl
	     << spacing << "	" << " PN:" << getPrettyName() << "\"" << endl
	     << spacing << "	::= { " << sanitize(getParent()->getName()) << " " << mOid->getLeaf() << " }" << endl;
}

GenericEntry::GenericEntry(const string& name, GenericValueType type, const string& help, uint64_t oid_index)
    : mName(name), mHelp(help), mType(type), mOidLeaf(oid_index) {
	mConfigListener = nullptr;
	size_t idx;
	for (idx = 0; idx < name.size(); idx++) {
		if (name[idx] == '_')
			throw BadConfiguration{"underscore characters not allowed in config items, please use minus sign (while "
			                       "checking generic entry name '" +
			                       name + "')"};
		if (type != Struct && isupper(name[idx])) {
			throw BadConfiguration{
			    "Uppercase characters not allowed in config items, please use lowercase characters only (while "
			    "checking generic entry name '" +
			    name + "')"};
		}
	}

	if (oid_index == 0) {
		mOidLeaf = Oid::oidFromHashedString(name);
	}
}

std::string GenericEntry::escapeDoubleQuotes(const std::string& str) {
	string escapedStr;
	for (auto& s : str) {
		if (s == '"') {
			escapedStr += "''";
		} else {
			escapedStr += s;
		}
	}
	return escapedStr;
}

void GenericEntry::setParent(GenericEntry* parent) {
	mParent = parent;
	mOid.emplace(parent->getOid(), mOidLeaf);
}

/*********************************************************************************************************************/

void ConfigValue::mibFragment(ostream& ost, const string& spacing) const {
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

void ConfigBoolean::mibFragment(ostream& ost, const string& spacing) const {
	string s("INTEGER { true(1),false(0) }");
	doConfigMibFragment(ost, s, spacing);
}
void ConfigInt::mibFragment(ostream& ost, const string& spacing) const {
	string s("Integer32");
	doConfigMibFragment(ost, s, spacing);
}
void StatCounter64::mibFragment(ostream& ost, const string& spacing) const {
	string s("Counter64");
	doMibFragment(ost, "", "read-only", s, spacing);
}
void GenericStruct::mibFragment(ostream& ost, const string& spacing) const {
	string parent = getParent() ? getParent()->getName() : "flexisipMIB";
	ost << spacing << sanitize(getName()) << "	" << "OBJECT IDENTIFIER ::= { " << sanitize(parent) << " "
	    << mOid->getLeaf() << " }" << endl;
}

void NotificationEntry::mibFragment(ostream& ost, const string& spacing) const {
	if (!getParent()) throw BadConfiguration{"no parent found for " + getName()};
	ost << spacing << sanitize(getName()) << " NOTIFICATION-TYPE" << endl
	    << spacing << "	OBJECTS	{	flNotifString	} " << endl
	    << spacing << "	STATUS	current" << endl
	    << spacing << "	DESCRIPTION" << endl
	    << spacing << "	\"" << escapeDoubleQuotes(getHelp()) << endl
	    << spacing << "	" << " PN:" << getPrettyName() << "\"" << endl
	    << spacing << "	::= { " << sanitize(getParent()->getName()) << " " << mOid->getLeaf() << " }" << endl;
}

NotificationEntry::NotificationEntry(const std::string& name, const std::string& help, uint64_t oid_index)
    : GenericEntry(name, Notification, help, oid_index) {
}

/* ConfigValue */

ConfigValue::ConfigValue(
    const string& name, GenericValueType vt, const string& help, const string& default_value, uint64_t oid_index)
    : GenericEntry(name, vt, help, oid_index), mValue(default_value), mDefaultValue(default_value) {
	mExportToConfigFile = true;
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
		LOGW << "'" << getCompleteName() << "' is not set but its old name is, falling back on '"
		     << mFallback->getCompleteName() << "'";

		return mFallback->get();
	}
	return mValue;
}

const string& ConfigValue::getDefault() const {
	return mDefaultValue;
}

std::string_view ConfigValue::getDefaultUnit() const {
	return "";
}

void ConfigValue::setFallback(const ConfigValue& fallbackValue) {
	mFallback = &fallbackValue;
}

/* Oid */

Oid::Oid(Oid& parent, uint64_t leaf) {
	mOidPath = parent.getValue();
	mOidPath.push_back(leaf);
}

Oid::Oid(vector<uint64_t>&& path, uint64_t leaf) {
	mOidPath = path;
	mOidPath.push_back(leaf);
}

Oid::Oid(vector<uint64_t>&& path) {
	mOidPath = path;
}

uint64_t Oid::oidFromHashedString(const string& str) {
	su_md5_t md5[1];
	su_md5_init(md5);
	su_md5_update(md5, str.c_str(), str.size());
	uint8_t digest[SU_MD5_DIGEST_SIZE];
	su_md5_digest(md5, digest);
	uint64_t oidValue = 0;
	for (int i = 0; i < 4; ++i) { // limit to half 32 bits [1]
		oidValue <<= 8;
		oidValue += digest[i];
	}
	return oidValue / 2; // takes only half the 32 bit size [1]
	                     // 1: snmpwalk cannot associate oid to name otherwise
}

void ConfigValue::setParent(GenericEntry* parent) {
	GenericEntry::setParent(parent);
}

GenericStruct::GenericStruct(const string& name, const string& help, uint64_t oid_index)
    : GenericEntry(name, Struct, help, oid_index) {
}

void GenericStruct::deprecateChild(const string& name, const DeprecationInfo& info) const {
	GenericEntry* e = find(name);
	if (e) e->setDeprecated(info);
}

void GenericStruct::addChildrenValues(ConfigItemDescriptor* items) {
	addChildrenValues(items, true);
}

void GenericStruct::addChildrenValues(ConfigItemDescriptor* items, bool hashed) {
	uint64_t cOid = 1;

	for (; items->name != nullptr; items++) {
		unique_ptr<GenericEntry> val = nullptr;
		if (hashed) cOid = Oid::oidFromHashedString(items->name);
		if (!items->name) {
			throw BadConfiguration{"no name provided in configuration item"};
		}
		if (!items->help) {
			throw BadConfiguration{"no help provided for configuration item '"s + items->name + "'"};
		}
		if (!items->default_value) {
			throw BadConfiguration{"no default value provided for configuration item '"s + items->name + "'"};
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
			case DurationMS:
				val = make_unique<ConfigDuration<std::chrono::milliseconds>>(items->name, items->help,
				                                                             items->default_value, cOid);
				break;
			case DurationS:
				val = make_unique<ConfigDuration<std::chrono::seconds>>(items->name, items->help, items->default_value,
				                                                        cOid);
				break;
			case DurationMIN:
				val = make_unique<ConfigDuration<std::chrono::minutes>>(items->name, items->help, items->default_value,
				                                                        cOid);
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
				throw BadConfiguration{"bad ConfigValue type " + to_string(items->type) + " for " + items->name};
		}
		addChild(std::move(val));
		if (!hashed) ++cOid;
	}
}

namespace {
constexpr auto finished = "-finished";
}

StatCounter64* GenericStruct::createStat(const string& name, const string& help) {
	uint64_t cOid = Oid::oidFromHashedString(name);
	auto val = make_unique<StatCounter64>(name, help, cOid);
	return addChild(std::move(val));
}
void GenericStruct::createStatPair(const string& name, const string& help) {
	createStat(name, help);
	createStat(name + finished, help + " Finished.");
}

StatCounter64* GenericStruct::getStat(const string& name) const {
	return get<StatCounter64>(name);
}

pair<StatCounter64*, StatCounter64*> GenericStruct::getStatPair(const string& name) const {
	return make_pair(getStat(name), getStat(name + finished));
}

unique_ptr<StatPair> GenericStruct::getStatPairPtr(const string& name) const {
	return make_unique<StatPair>(getStat(name), getStat(name + finished));
}

struct matchEntryNameApprox {
	const string mName;
	explicit matchEntryNameApprox(const string& name) : mName(name) {
	}
	bool operator()(const unique_ptr<GenericEntry>& e) {
		auto min_required = mName.size() - 2;
		decltype(min_required) count = 0;
		if (min_required < 1) return false;

		for (const auto& c : mName) {
			if (e->getName().find(c) != string::npos) {
				count++;
			}
		}
		if (count >= min_required) {
			return true;
		}
		return false;
	}
};

GenericEntry* GenericStruct::findApproximate(const string& name) const {
	auto it = find_if(mEntries.begin(), mEntries.end(), matchEntryNameApprox(name));
	if (it != mEntries.end()) return it->get();
	return nullptr;
}

const list<unique_ptr<GenericEntry>>& GenericStruct::getChildren() const {
	return mEntries;
}

ConfigBoolean::ConfigBoolean(const string& name, const string& help, const string& default_value, uint64_t oid_index)
    : ConfigValue(name, Boolean, help, default_value, oid_index) {
}

bool ConfigBoolean::parse(const string& value) {
	if (value == "true" || value == "1") return true;
	else if (value == "false" || value == "0") return false;
	throw BadConfiguration{"bad boolean value '" + value + "'"};
	return false;
}

bool ConfigBoolean::read() const {
	return parse(get());
}
bool ConfigBoolean::readNext() const {
	return parse(getNextValue());
}

void ConfigBoolean::write(bool value) {
	set(value ? "1" : "0");
}

ConfigInt::ConfigInt(const string& name, const string& help, const string& default_value, uint64_t oid_index)
    : ConfigValue(name, Integer, help, default_value, oid_index) {
}

int ConfigInt::read() const {
	return stoi(get());
}

void ConfigInt::write(int value) {
	std::ostringstream oss;
	oss << value;
	set(oss.str());
}

ConfigIntRange::ConfigIntRange(const std::string& name,
                               const std::string& help,
                               const std::string& default_value,
                               uint64_t oid_index)
    : ConfigValue(name, IntegerRange, help, default_value, oid_index) {
}

ConfigIntRange::RangeBounds ConfigIntRange::parse(const string& value) {
	auto bounds = RangeBounds();
	try {
		if (const auto range = StringUtils::splitOnce(value, "-"); range != nullopt) {
			bounds.min = stoi(string{range->first});
			bounds.max = stoi(string{range->second});
		} else {
			bounds.min = bounds.max = stoi(value);
		}
	} catch (const invalid_argument&) {
		throw invalid_argument{"ConfigIntRange::parse(), no conversion could be performed (\"" + getCompleteName() +
		                       "\" = " + value + ")"};
	} catch (const out_of_range&) {
		throw out_of_range{"ConfigIntRange::parse(), converted value is out of range (target: int, \"" +
		                   getCompleteName() + "\" = " + value + ")"};
	}
	return bounds;
}

int ConfigIntRange::readMin() {
	return parse(get()).min;
}
int ConfigIntRange::readMax() {
	return parse(get()).max;
}

void ConfigIntRange::write(int min, int max) {
	if (min > max) {
		throw BadConfiguration{"min (" + to_string(min) + ") > max (" + to_string(max) + ") (ConfigIntRange)"};
	} else {
		std::ostringstream oss;
		oss << min << "-" << max;
		set(oss.str());
	}
}

StatCounter64::StatCounter64(const string& name, const string& help, uint64_t oid_index)
    : GenericEntry(name, Counter64, help, oid_index) {
	mValue = 0;
}

ConfigString::ConfigString(const string& name, const string& help, const string& default_value, uint64_t oid_index)
    : ConfigValue(name, String, help, default_value, oid_index) {
}
ConfigString::~ConfigString() = default;

ConfigRuntimeError::ConfigRuntimeError(const string& name, const string& help, uint64_t oid_index)
    : ConfigValue(name, RuntimeError, help, "", oid_index) {
	this->setReadOnly(true);
	this->mExportToConfigFile = false;
}

const string& ConfigString::read() const {
	return get();
}

ConfigByteSize::ConfigByteSize(const string& name, const string& help, const string& default_value, uint64_t oid_index)
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

void ConfigRuntimeError::writeErrors(const GenericEntry* entry, ostringstream& oss) const {
	const auto* cs = dynamic_cast<const GenericStruct*>(entry);
	if (cs) {
		const auto& children = cs->getChildren();
		for (auto& child : children) {
			writeErrors(child.get(), oss);
		}
	}

	if (!entry->getErrorMessage().empty()) {
		if (oss.tellp() > 0) oss << "|";
		oss << entry->getOidAsString() << ":" << entry->getErrorMessage();
	}
}

string ConfigRuntimeError::generateErrors() const {
	ostringstream oss;
	auto* root = retrieveRoot(this);
	writeErrors(root, oss);
	return oss.str();
}

ConfigStringList::ConfigStringList(const string& name,
                                   const string& help,
                                   const string& default_value,
                                   uint64_t oid_index)
    : ConfigValue(name, StringList, help, default_value, oid_index) {
}

#define DELIMITERS " \n,"

list<string> ConfigStringList::parse(const std::string& in) {
	list<string> retlist;
	char* res = strdup(in.c_str());
	char* saveptr = nullptr;
	char* ret = strtok_r(res, DELIMITERS, &saveptr);
	while (ret != nullptr) {
		retlist.emplace_back(ret);
		ret = strtok_r(nullptr, DELIMITERS, &saveptr);
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
                                                 uint64_t oid_index)
    : ConfigValue(name, BooleanExpr, help, default_value, oid_index) {
}

shared_ptr<SipBooleanExpression> ConfigBooleanExpression::read() const {
	return SipBooleanExpressionBuilder::get().parse(get());
}

std::vector<std::function<void(GenericStruct&)>>& ConfigManager::defaultInit() {
	static std::vector<std::function<void(GenericStruct&)>> defaultConf;
	return defaultConf;
}

RootConfigStruct::RootConfigStruct(const string& name,
                                   const string& help,
                                   vector<uint64_t> oid_root_path,
                                   const std::string& configFile)
    : GenericStruct(name, help, 1), mConfigFile(configFile) {
	mOid.emplace(std::move(oid_root_path), 1);
}

RootConfigStruct::~RootConfigStruct() {
}

#ifndef DEFAULT_LOG_DIR
#define DEFAULT_LOG_DIR "/var/opt/belledonne-communications/log/flexisip"
#endif

ConfigManager::ConfigManager()
    : mConfigRoot("flexisip",
                  "This is the default Flexisip (v" FLEXISIP_GIT_VERSION ") configuration file",
                  {1, 3, 6, 1, 4, 1, SNMP_COMPANY_OID},
                  mConfigFile),
      mReader(&mConfigRoot) {
	// to make sure global_conf is instantiated first
	static ConfigItemDescriptor global_conf[] = {
	    {
	        StringList,
	        "default-servers",
	        "Servers started by default when '--server' is not specified in the command line. "
	        "Possible values are: 'proxy', 'presence', 'conference', 'regevent' and 'b2bua'. Each value must be "
	        "separated by a whitespace.",
	        "proxy",
	    },
	    {
	        Boolean,
	        "auto-respawn",
	        "Automatically respawn Flexisip in case of abnormal termination (crashes). "
	        "This only has an effect if Flexisip is launched with '--daemon' option",
	        "true",
	    },
	    {
	        String,
	        "plugins-dir",
	        "Path to the directory that contains plugins.",
	        DEFAULT_PLUGINS_DIR,
	    },
	    {
	        StringList,
	        "plugins",
	        "Plugins to load.\n"
	        "The list of installed plugins can be found at <prefix>/lib/flexisip/plugins.\n"
	        "The name of a plugin can be built from the corresponding library name by removing the extension and the "
	        "'lib' prefix.\n"
	        "Example: 'test' will load libtest.so at runtime.",
	        "",
	    },
	    {
	        Boolean,
	        "dump-corefiles",
	        "Generate a core dump on crash.\n"
	        "On GNU/Linux, the action to do on core dump is defined by the kernel file "
	        "'/proc/sys/kernel/core_pattern'.\n"
	        "On recent distributions like RHEL 8, the generated core dumps are given by default to the core manager of "
	        "SystemD. Core dumps can easily be listed by using the coredumpctl(1) command.\n"
	        "On older distributions, core dumps are often written in the root ('/') directory. If your root directory "
	        "has little available space, it is recommended to relocate your core dumps in another place by modifying "
	        "the 'core_pattern' file on system boot. This can be done by adding the following line in "
	        "'/etc/rc.local':\n"
	        "    echo '/home/cores/core.\%e.\%t.\%p' > /proc/sys/kernel/core_pattern\n"
	        "\n"
	        "See core(5) manual for more information about core handling on GNU/Linux.",
	        "false",
	    },
	    {
	        Boolean,
	        "enable-snmp",
	        "Enable SNMP.",
	        "false",
	    },

	    // Logging settings.
	    {
	        String,
	        "log-directory",
	        "Path to the directory where log files will be created.\n"
	        "WARNING: Flexisip has no embedded log rotation system but provides a configuration file for logrotate.\n"
	        "Please make sure that logrotate is installed and running on your system in order to have Flexisip's logs "
	        "rotated. Log rotation can be customized by editing /etc/logrotate.d/flexisip-logrotate.",
	        DEFAULT_LOG_DIR,
	    },
	    {
	        String,
	        "log-filename",
	        "Name of the log file\n."
	        "The string '{server}' is a placeholder that is replaced with the corresponding server type. If several "
	        "server types are specified, then '{server}' will be replaced by the concatenation of all server types "
	        "separated by a '+' character.\n"
	        "Example: 'proxy+presence'.",
	        "flexisip-{server}.log",
	    },
	    {
	        String,
	        "log-level",
	        "Logging verbosity.\n"
	        "Possible values are: 'debug', 'message', 'warning' and 'error'",
	        "error",
	    },
	    {
	        String,
	        "syslog-level",
	        "Syslog logging verbosity.\n"
	        "Possible values are: 'debug', 'message', 'warning' and 'error'",
	        "error",
	    },
	    {
	        Integer,
	        "sofia-level",
	        "Sofia-SIP logging verbosity.\n"
	        "These logs are only displayed if 'log-level' is set to 'debug' or if the program is started with the '-d' "
	        "(--debug) option. The verbosity levels range from 1 to 9:\n"
	        "    1 -> Critical errors\n"
	        "    2 -> Non-critical errors\n"
	        "    3 -> Warnings and progress messages\n"
	        "    5 -> Signaling protocol actions\n"
	        "    7 -> Media protocol actions\n"
	        "    9 -> Entering/exiting functions",
	        "5",
	    },
	    {
	        Boolean,
	        "user-errors-logs",
	        "Log user errors (on a different logging domain).\n"
	        "Examples: authentication operations, registration events, requests routing, etc...",
	        "false",
	    },
	    {
	        String,
	        "contextual-log-filter",
	        "A boolean expression applied to the processing of all SIP requests.\n"
	        "When the expression evaluates to 'true', use the 'contextual-log-level' logging level for all the logs "
	        "generated during the processing of the current request. This is useful to debug a certain scenario on a "
	        "production environment.\n"
	        "The definition of SIP boolean expressions is the same as for entry filters of modules, which is "
	        "documented here: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Filter%20syntax/",
	        "",
	    },
	    {
	        String,
	        "contextual-log-level",
	        "Logging verbosity of contextual logs.",
	        "debug",
	    },
	    {
	        String,
	        "show-body-for",
	        "A boolean expression applied to the processing of all SIP requests.\n"
	        "When the expression evaluates to 'true', log the request body. Cannot be empty, use 'true' or 'false' "
	        "instead.\n"
	        "The definition of SIP boolean expressions is documented here: "
	        "https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Filter%20syntax/\n"
	        "Example: content-type == 'application/sdp' && request.method == 'MESSAGE'",
	        "content-type == 'application/sdp'",
	    },

	    // Network settings.
	    {
	        StringList,
	        "transports",
	        "List of whitespace separated SIP URIs where the proxy must listen.\n"
	        "Wildcard (*) means 'all local ip addresses'. If the 'transport' parameter is not specified, the server "
	        "will listen on both UDP and TCP transports. A local address to bind onto can be specified using the "
	        "'maddr' SIP URI parameter. The domain part of SIP URIs are used as public domain or ip address.\n"
	        "The 'sips' transport definition accepts some optional parameters:\n"
	        " - 'tls-certificates-dir': path, has the same meaning as the 'tls-certificates-dir' parameter of this "
	        "section (overriding only applies for the current SIP URI).\n"
	        " - 'tls-certificates-file': file path, has the same meaning as the 'tls-certificates-file' parameter of "
	        "this section (overriding only applies for the current SIP URI).\n"
	        " - 'tls-certificates-private-key': file path, has the same meaning as the 'tls-certificates-private-key' "
	        "parameter of this section (overriding only applies for the current SIP URI).\n"
	        " - 'tls-certificates-ca-file': file path, has the same meaning as the 'tls-certificates-ca-file' "
	        "parameter of this section (overriding only applies for the current SIP URI).\n"
	        " - 'tls-verify-incoming': value in {'0', '1'}, indicates whether clients are required to present a valid "
	        "client certificate or not (defaults to '0').\n"
	        " - 'tls-allow-missing-client-certificate': value in {'0', '1'}, allow connections from clients that have "
	        "no certificate even if `tls-verify-incoming` is enabled (useful if you want Flexisip to ask for a client "
	        "certificate but do not fail if the client cannot provide one).\n"
	        " - 'tls-verify-outgoing': value in {'0', '1'}, whether Flexisip should verify the peer certificate when "
	        "it creates an outgoing TLS connection to another server (defaults to '1').\n"
	        " - 'require-peer-certificate': (deprecated) same as 'tls-verify-incoming'\n"
	        "\n"
	        "It is HIGHLY RECOMMENDED to specify a canonical name for 'sips' transports, so that the proxy can "
	        "advertise this information in 'Record-Route' headers, which allows TLS cname verifications to be "
	        "performed by clients.\n"
	        "Specifying a SIP URI with 'transport=tls' is not allowed: the 'sips' scheme must be used instead. As "
	        "requested by SIP RFC, IPv6 addresses must be enclosed within brackets.\n"
	        "\n"
	        "Here are some examples to understand:\n"
	        " - listen on all local interfaces for UDP and TCP, on standard port:\n"
	        "\ttransports=sip:*\n"
	        " - listen on all local interfaces for UDP, TCP and TLS, on standard ports:\n"
	        "\ttransports=sip:* sips:*\n"
	        " - listen only a specific IPv6 interface, on standard ports, with UDP, TCP and TLS\n"
	        "\ttransports=sip:[2a01:e34:edc3:4d0:7dac:4a4f:22b6:2083] sips:[2a01:e34:edc3:4d0:7dac:4a4f:22b6:2083]\n"
	        " - listen on TLS localhost with 2 different ports and SSL certificates:\n"
	        "\ttransports=sips:localhost:5061;tls-certificates-dir=path_a "
	        "sips:localhost:5062;tls-certificates-dir=path_b\n"
	        " - listen on TLS localhost with 2 peer certificate requirements:\n"
	        "\ttransports=sips:localhost:5061;tls-verify-incoming=0 sips:localhost:5062;tls-verify-incoming=1\n"
	        " - listen on 192.168.0.29:6060 with TLS, but public hostname is 'sip.linphone.org' used in SIP requests. "
	        "Bind address won't appear in requests:\n"
	        "\ttransports=sips:sip.linphone.org:6060;maddr=192.168.0.29",
	        "sip:*",
	    },
	    {
	        StringList,
	        "aliases",
	        "List of whitespace separated host names pointing to this machine.\n"
	        "This is to prevent loops while routing SIP requests.",
	        "localhost",
	    },
	    {
	        DurationS,
	        "idle-timeout",
	        "Time interval after which inactive connections are closed.",
	        "3600",
	    },
	    {
	        DurationS,
	        "keepalive-interval",
	        "Time interval for sending \"\\r\\n\\r\\n\" keepalive packets on inbound and outbound connections.\n"
	        "The main purpose of sending keepalive packets is to keep connections alive across NATs. It also helps to "
	        "detect silently broken connections which can reduce the number of socket descriptors used by Flexisip. A "
	        "value of zero deactivates this feature",
	        "1800",
	    },
	    {
	        DurationS,
	        "proxy-to-proxy-keepalive-interval",
	        "Time interval for sending \"\\r\\n\\r\\n\" keepalive packets for proxy-to-proxy connections.\n"
	        "Indeed, while it is undesirable to send frequent keepalive packets to mobile clients (it drains their "
	        "battery), sending frequent keepalive packets has proven to be helpful to keep connections up between "
	        "proxy nodes in a very popular US virtualized datacenter. A value of zero deactivates this feature.",
	        "0",
	    },
	    {
	        DurationMS,
	        "transaction-timeout",
	        "SIP transaction timeout.\n"
	        "Set to T1*64 by default.",
	        "32000",
	    },
	    {
	        Integer,
	        "udp-mtu",
	        "The UDP MTU.\n"
	        "Flexisip will fallback to TCP when sending a request whose size exceeds the UDP MTU. Please read "
	        "https://sofia-sip.sourceforge.net/refdocs/nta/nta__tag_8h.html#a6f51c1ff713ed4b285e95235c4cc999a "
	        "for more details. If sending large packets over UDP is not a problem, then set a big value such as 65535. "
	        "Unlike the recommendation of the RFC, the default value of UDP MTU is 1460 in Flexisip (instead of 1300).",
	        "1460",
	    },
	    {
	        Integer,
	        "tcp-max-read-size",
	        "Maximum number of bytes read at once when extracting data from a TCP socket. "
	        "WARNING: a SIP request (headers + body) cannot exceed this amount of bytes otherwise the parsing will "
	        "fail",
	        "524288",
	    },
	    {
	        StringList,
	        "rtp-bind-address",
	        "Bind address for all RTP streams (MediaRelay and Transcoder).\n"
	        "This parameter is only useful for some specific networks, keeping the default value is recommended.",
	        "0.0.0.0 ::0",
	    },

	    // TLS settings.
	    {
	        String,
	        "tls-certificates-dir",
	        "Path to the directory where TLS server certificates and private keys can be found.\n"
	        "Certificates must be concatenated inside an 'agent.pem' file. Any chain certificates must be put into a "
	        "file named 'cafile.pem'. The setup of 'agent.pem', and eventually 'cafile.pem' is required for TLS "
	        "transport to work.",
	        "/etc/flexisip/tls/",
	    },
	    {
	        DurationMIN,
	        "tls-certificates-check-interval",
	        "Interval at which the server will check if TLS certificates have been updated. Apply update once "
	        "detected.",
	        "1",
	    },
	    {
	        String,
	        "tls-certificates-file",
	        "Path to the file containing the server certificate chain.\n"
	        "The file must be in PEM format, see OpenSSL SSL_CTX_use_certificate_chain_file documentation. If used, "
	        "'tls-certificates-private-key' MUST be set.",
	        "",
	    },
	    {
	        String,
	        "tls-certificates-private-key",
	        "Path to the file containing the private key.\n"
	        "See OpenSSL SSL_CTX_use_PrivateKey_file documentation. If used, 'tls-certificates-file' MUST be set.",
	        "",
	    },
	    {
	        String,
	        "tls-certificates-ca-file",
	        "Path to the file containing CA certificates.\n"
	        "See OpenSSL SSL_CTX_load_verify_locations and SSL_CTX_set_client_CA_list documentation. Can be empty.",
	        "",
	    },
	    {
	        String,
	        "tls-ciphers",
	        "Cipher strings to pass to OpenSSL in order to limit the cipher suites to use while establishing TLS "
	        "sessions.\n"
	        "Please take a look at ciphers(1) UNIX manual to get the list of supported keywords by your current "
	        "version of OpenSSL. You might visit https://www.openssl.org/docs/manmaster/man1/ciphers.html too. The "
	        "default value set by Flexisip should provide a high level of security while keeping an acceptable level "
	        "of interoperability with currently deployed clients on the market.",
	        "HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL",
	    },
	    {
	        Boolean,
	        "require-peer-certificate",
	        "Ask for client certificate on TLS session establishing.",
	        "false",
	    },

	    // Other settings.
	    {
	        String,
	        "unique-id",
	        "Unique ID used to identify this Flexisip instance.\n"
	        "It must be a randomly generated 16-sized hexadecimal number. If empty, it will be generated each time "
	        "Flexisip starts.",
	        "",
	    },
	    {
	        Integer,
	        "tport-message-queue-size",
	        "Number of SIP requests that Sofia-SIP can queue in a transport (a connection). "
	        "It is 64 by default, hardcoded in Sofia-SIP (Sofia-SIP also used to hardcode a maximum value of 1000). "
	        "This is not sufficient for instant messaging applications.",
	        "1000",
	    },
	    {
	        DurationS,
	        "memory-usage-log-interval",
	        "Interval between logs about server memory usage.\n"
	        "This feature periodically logs the value occupied in RAM by the process (VmRSS). These logs use debug "
	        "level.\n"
	        "Only works on Linux.\n"
	        "Set to 0 in order to disable the feature.",
	        "0",
	    },

	    // Deprecated parameters.
	    {
	        ByteSize,
	        "max-log-size",
	        "Max size of a log file before switching to a new log file, expressed with units. "
	        "For example: 10G, 100M. If -1 then there is no maximum size",
	        "-1",
	    },
	    {
	        Boolean,
	        "use-maddr",
	        "Allow flexisip to use maddr in sips connections to verify the CN of the TLS "
	        "certificate.",
	        "false",
	    },
	    {
	        Boolean,
	        "use-rfc2543-record-route",
	        "Allow Flexisip to use the deprecated param 'transport=tls' in record-route header.",
	        "false",
	    },

	    config_item_end,
	};

	static ConfigItemDescriptor cluster_conf[] = {
	    {
	        Boolean,
	        "enabled",
	        "Enable cluster mode.\n"
	        "If 'false', the parameters of the [cluster] section will not have any effect.",
	        "false",
	    },
	    {
	        String,
	        "cluster-domain",
	        "Domain name that enables external SIP agents to access to the cluster.\n"
	        "Such domain is often associated to DNS SRV records for each proxy of the cluster, so that DNS resolution "
	        "returns the address of a specific proxy randomly.\n"
	        "Flexisip uses that domain when it needs to insert a 'Path' or 'Record-route' header addressing the "
	        "cluster instead of itself.",
	        "",
	    },
	    {
	        StringList,
	        "nodes",
	        "List of IP addresses of all the proxies present in the cluster.\n"
	        "SIP requests coming from these addresses won't be challenged by the authentication module and won't have "
	        "any rate limit applied by the DosProtection module.",
	        "",
	    },
	    {
	        String,
	        "internal-transport",
	        "Transport to use for communication with the other proxies of the cluster.\n"
	        "This is only useful when no transport declared in 'global/transport' parameter can be used to reach the "
	        "other proxies (e.g. when inter-proxy communications are to be made through a private network).\n"
	        "Example: sip:10.0.0.8:5059;transport=tcp",
	        "",
	    },
	    config_item_end,
	};

	static ConfigItemDescriptor mdns_conf[] = {
	    {
	        Boolean,
	        "enabled",
	        "Enable multicast DNS register",
	        "false",
	    },
	    {
	        IntegerRange,
	        "mdns-priority",
	        "Priority of this instance, lower value means more 'preferred'.\n"
	        "'n': priority of n (example: 10)\n"
	        "'n-m': random priority between n and m (example: 10-50)",
	        "0",
	    },
	    {
	        Integer,
	        "mdns-weight",
	        "A relative weight for Flexisip instances with the same priority.\n"
	        "Higher values means more 'preferred'.\n"
	        "For example, if two Flexisip instances are registered on the same local domain with one at '20' and the "
	        "other at '80', then 20% of the traffic will be redirected to the first instance and 80% to the other "
	        "one.\n"
	        "The sum of all the weights of Flexisip instances on the same local domain must be 100.",
	        "100",
	    },
	    {
	        DurationMS,
	        "mdns-ttl",
	        "Time To Live of any mDNS query that will ask for this Flexisip instance",
	        "3600",
	    },
	    config_item_end,
	};

	auto uNotifObjs = make_unique<GenericStruct>("notif", "Templates for notifications.", 1);
	uNotifObjs->setExportable(false);
	auto notifObjs = mConfigRoot.addChild(std::move(uNotifObjs));
	auto uNotifier = make_unique<NotificationEntry>("sender", "Send notifications", 1);
	notifObjs->addChild(std::move(uNotifier));
	auto nmsg = make_unique<ConfigString>("msg", "Notification message payload.", "", 10);
	nmsg->setNotifPayload(true);
	notifObjs->addChild(std::move(nmsg));
	auto nsoid = make_unique<ConfigString>("source", "Notification source payload.", "", 11);
	nsoid->setNotifPayload(true);
	notifObjs->addChild(std::move(nsoid));

	auto uGlobal = make_unique<GenericStruct>("global", "Some global settings of the flexisip proxy.", 2);
	auto global = mConfigRoot.addChild(std::move(uGlobal));
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
	global->addChild(std::move(version));

	auto runtimeError = make_unique<ConfigRuntimeError>("runtime-error", "Retrieve current runtime error state.", 998);
	runtimeError->setExportable(false);
	runtimeError->setReadOnly(true);
	global->addChild(std::move(runtimeError));

	auto uCluster = make_unique<GenericStruct>(
	    "cluster",
	    "This section contains some parameters useful when the current proxy is part of a network of proxies (cluster) "
	    "which serve the same domain.",
	    0);
	auto cluster = mConfigRoot.addChild(std::move(uCluster));
	cluster->addChildrenValues(cluster_conf);
	cluster->setReadOnly(true);

	auto uMdns = make_unique<GenericStruct>(
	    "mdns-register", "Should the server be registered on a local domain, to be accessible via multicast DNS.", 0);
	auto* mdns = mConfigRoot.addChild(std::move(uMdns));
	mdns->addChildrenValues(mdns_conf);
	mdns->setReadOnly(true);

	// initialize default conf for statically registered sections
	for (const auto& vec : defaultInit()) {
		vec(mConfigRoot);
	}

	// add agent and modules sections
	Agent::addConfigSections(*this);
}

bool ConfigManager::doIsValidNextConfig([[maybe_unused]] const ConfigValue& cv) {
	return true;
}

bool ConfigManager::doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) {
	switch (state) {
		case ConfigState::Check:
			return doIsValidNextConfig(conf);
		case ConfigState::Changed:
			mDirtyConfig = true;
			break;
		case ConfigState::Reset:
			mDirtyConfig = false;
			break;
		case ConfigState::Committed:
			if (mDirtyConfig) {
				LOGI << "Scheduling server restart to apply new config";
				mDirtyConfig = false;
				mNeedRestart = true;
			}
			break;
	}
	return true;
}

int ConfigManager::load(const std::string& configfile) {
	LOGI << "Loading config file " << configfile;
	mConfigFile = configfile;
	int res = mReader.read(configfile);

	// Plugins are specified in configuration file
	// Load them, add their configuration sections and reload config
	if (!getGlobal()->get<ConfigStringList>("plugins")->read().empty()) {
		Agent::addPluginsConfigSections(*this);
		mReader.reload();
	}

	mReader.checkUnread();
	applyOverrides(true);
	return res;
}

void ConfigManager::applyOverrides(bool strict) {
	for (auto& it : mOverrides) {
		const std::string& key = it.first;
		const std::string& value = it.second;
		if (value.empty()) continue;
		auto val = mConfigRoot.getDeep<ConfigValue>(key, strict);
		if (val) val->set(value);
		else {
			LOGUE << "Skipping config override " << key << ":" << value;
		}
	}
}

const GenericStruct* ConfigManager::getRoot() const {
	return &mConfigRoot;
}

GenericStruct* ConfigManager::getRoot() {
	return &mConfigRoot;
}

const GenericStruct* ConfigManager::getGlobal() const {
	return mConfigRoot.get<GenericStruct>("global");
}

int FileConfigReader::read(const std::string& filename) {
	int err;
	mFilename = filename;
	mCfg = make_unique<LpConfig>();
	err = mCfg->readFile(filename);
	read2(mRoot, 0);
	return err;
}

int FileConfigReader::reload() {
	read2(mRoot, 0);
	return 0;
}

void FileConfigReader::checkUnread() {
	auto onUnreadItem = [&](const string& secname, const string& key, int lineno) {
		ostringstream ss;
		ss << "Unsupported parameter '" << key << "' in section [" << secname << "] at line " << lineno << ".";
		mHaveUnreads = true;
		GenericEntry* sec = mRoot->find(secname);
		if (sec == nullptr) {
			sec = mRoot->findApproximate(secname);
			if (sec != nullptr) {
				ss << " Unknown section '[" << secname << "]', did you mean '[" << sec->getName().c_str()
				   << "]' instead?";
			} else {
				ss << " Unknown section '[" << secname << "]'.";
			}
		} else {
			auto st = dynamic_cast<GenericStruct*>(sec);
			if (st) {
				GenericEntry* val = st->find(key);
				if (val == nullptr) {
					val = st->findApproximate(key);
					if (val != nullptr) {
						ss << " Did you mean '" << val->getName().c_str() << "'?";
					}
				}
			}
		}
		LOGE_CTX(mLogPrefix, "checkUnread") << ss.str();
	};
	mCfg->processUnread(std::function<void(const string& secname, const string& key, int lineo)>(onUnreadItem));
	if (mHaveUnreads)
		throw BadConfiguration{
		    "some items or sections are invalid in the configuration, please verify your configuration file"};
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
		if (level < 2) throw BadConfiguration{"ConfigValues at root level are not allowed"};
		if (level > 2) throw BadConfiguration{"the current file format does not support recursive subsections"};

		const char* val = mCfg->getString(cv->getParent()->getName(), cv->getName(), nullptr);
		if (val) {
			if (cv->isDeprecated()) {
				const auto& info = cv->getDeprecationInfo();
				LOGW << "Deprecated parameter:\n"
				     << "\t[" << cv->getParent()->getName() << "/" << cv->getName() << "]\n"
				     << "\t" << info.getText() << "\n"
				     << "\tDeprecated since " << info.getDate() << " (Flexisip v" << info.getVersion() << ")\n";
			}
			try {
				cv->set(val);
			} catch (std::exception& e) {
				throw BadConfiguration{"caught an exception while reading '" + mFilename + "' (" + e.what() + ")"};
			}
		} else {
			cv->restoreDefault();
		}
	}
	return 0;
}

FileConfigReader::FileConfigReader(GenericStruct* root) : mRoot(root), mHaveUnreads(false) {
}

FileConfigReader::~FileConfigReader() = default;

void GenericEntry::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitGenericEntry(*this);
}
void GenericStruct::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitGenericStruct(*this);
}
void RootConfigStruct::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitRootConfigStruct(*this);
}
void StatCounter64::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitStatCounter64(*this);
}
void ConfigValue::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigValue(*this);
}
void ConfigBoolean::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigBoolean(*this);
}
void ConfigInt::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigInt(*this);
}
void ConfigIntRange::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigIntRange(*this);
}
template <typename DurationType>
void ConfigDuration<DurationType>::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigDuration(*this);
}
template void ConfigDuration<std::chrono::milliseconds>::acceptVisit(ConfigManagerVisitor&);
template void ConfigDuration<std::chrono::seconds>::acceptVisit(ConfigManagerVisitor&);
template void ConfigDuration<std::chrono::minutes>::acceptVisit(ConfigManagerVisitor&);

void ConfigRuntimeError::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigRuntimeError(*this);
}
void ConfigString::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigString(*this);
}
void ConfigByteSize::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigByteSize(*this);
}
void ConfigStringList::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigStringList(*this);
}
void ConfigBooleanExpression::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitConfigBooleanExpression(*this);
}
void NotificationEntry::acceptVisit(ConfigManagerVisitor& visitor) {
	visitor.visitNotificationEntry(*this);
}

} // namespace flexisip