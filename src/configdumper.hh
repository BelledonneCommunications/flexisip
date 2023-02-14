/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2015  Belledonne Communications SARL.

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

#pragma once

#include <flexisip/configmanager.hh>
#include <iostream>

namespace flexisip {

class ConfigDumper {
public:
	ConfigDumper(GenericEntry *root) : mRoot(root) {}
	virtual ~ConfigDumper() = default;

	void setDumpExperimentalEnabled(bool enabled) {mDumpExperimental = enabled;}

	/**
	 * Can be overloaded for special handling. We expect the implementation to perform a recursive dump of all childrens
	 * of the root GenericEntry.
	*/
	virtual std::ostream &dump(std::ostream &ostr) const;

protected:
	/* Required dump function */

	/**
	 * When called, we expect the implementation to output into ostr the module description.
	 * @param ostr output stream
	 * @param moduleHead the module configuration entry
	 * @param level When the entry is not the root entry, this represents the current recursive level (>0)
	 * @return the output stream
	 */
	virtual std::ostream &dumpModuleHead(std::ostream &ostr, const GenericStruct *moduleHead, int level) const = 0;

	/**
	 * When called, we expect the implementation to output into ostr the value description.
	 * @param ostr output stream
	 * @param moduleHead the value configuration entry
	 * @param level When the entry is not the root entry, this represents the current recursive level (>0).
	 *		You can use this to perform the necessary indentation into the output stream.
	 * @return the output stream
	 */
	virtual std::ostream &dumpModuleValue(std::ostream &ostr, const ConfigValue *value, int level) const = 0;

	/**
	 * @brief Called when the module has finished dumping all the values.
	 *
	 * This allows to close some anchors that might have been needed for tabular representation.
	 * Since this is not strictly required, the function is implemented in the basic dumper as a noop.
	 *
	 * @param ostr output stream
	 * @param module the module that was dumped
	 * @param level recursion level
	 * @return the output stream
	 */
	virtual std::ostream &dumpModuleEnd(std::ostream &ostr, [[maybe_unused]] const GenericStruct *module, [[maybe_unused]] int level) const {return ostr;}

	/**
	 * Will tell if the module should be dumped. If the module is experimental and the dumpExperimental flag is
	 * not set, this will return false.
	 * @note This function is used internally, but can be used if the \ref dump() method is overriden
	 * @param moduleName the name of the module
	 * @return true if the module should be dumped, false otherwise.
	 */
	bool shouldDumpModule(const std::string &moduleName) const;

private:
	std::ostream &dump_recursive(std::ostream &ostr, const GenericEntry *root, unsigned int level) const;

protected:
	GenericEntry *mRoot = nullptr;
	bool mDumpExperimental = false;
};

inline std::ostream &operator<<(std::ostream &ostr, const ConfigDumper &dumper) {
	return dumper.dump(ostr);
}

/* File config dumper, used to rewrite the configuration file when needed. */

class FileConfigDumper : public ConfigDumper {
public:

	enum class Mode {
		CurrentValue, /** The value of the parameter will be dump as is, even if it is empty */
		DefaultValue, /** The value of the parameter will be systematically overridden by the default value */
		DefaultIfUnset /** The value of the parameter will be overridden by the default value, should the value be empty */
	};

	FileConfigDumper(GenericEntry *root) : ConfigDumper(root) {}

	/**
	 * Set the policy to use for generating the value of each parameter in the file.
	 */
	void setMode(Mode mode) {mDumpMode = mode;}

protected:
	std::ostream &dumpModuleHead(std::ostream &ostr, const GenericStruct *moduleHead, int level) const override;
	std::ostream &dumpModuleValue(std::ostream &ostr, const ConfigValue *value, int level) const override;

private:
	std::ostream &printHelp(std::ostream &os, const std::string &help, const std::string &comment_prefix) const;

	Mode mDumpMode = Mode::DefaultValue;
};

class TexFileConfigDumper : public ConfigDumper {
public:
	TexFileConfigDumper(GenericEntry *root) : ConfigDumper(root) {}

protected:
	std::ostream &dumpModuleHead(std::ostream &ostr, const GenericStruct *moduleHead, int level) const override;
	std::ostream &dumpModuleValue(std::ostream &ostr, const ConfigValue *value, int level) const override;

private:
	std::string escape(const std::string &strc) const;
};

class DokuwikiConfigDumper : public ConfigDumper {
public:
	DokuwikiConfigDumper(GenericEntry *root) : ConfigDumper(root) {}

protected:
	std::ostream &dumpModuleHead(std::ostream &ostr, const GenericStruct *moduleHead, int level) const override;
	std::ostream &dumpModuleValue(std::ostream &ostr, const ConfigValue *value, int level) const override;
};

class MediaWikiConfigDumper : public ConfigDumper {
public:
	MediaWikiConfigDumper(GenericEntry *root) : ConfigDumper(root) {}

protected:
	std::ostream &dumpModuleHead(std::ostream &ostr, const GenericStruct *moduleHead, int level) const override;
	std::ostream &dumpModuleValue(std::ostream &ostr, const ConfigValue *value, int level) const override;
	std::ostream &dumpModuleEnd(std::ostream &ostr, const GenericStruct *value, int level) const override;
};

class XWikiConfigDumper : public ConfigDumper {
public:
	XWikiConfigDumper(GenericEntry *root) : ConfigDumper(root) {}

protected:
	std::ostream &dumpModuleHead(std::ostream &ostr, const GenericStruct *moduleHead, int level) const override;
	std::ostream &dumpModuleValue(std::ostream &ostr, const ConfigValue *value, int level) const override;

	static std::string escape(const std::string &str);
};

class MibDumper : public ConfigDumper {
public:
	MibDumper(GenericEntry *root) : ConfigDumper(root) {}
	std::ostream &dump(std::ostream &ostr) const override;

protected:
	std::ostream &dumpModuleHead(std::ostream &ostr, [[maybe_unused]] const GenericStruct *moduleHead, [[maybe_unused]] int level) const override {return ostr;}
	std::ostream &dumpModuleValue(std::ostream &ostr, [[maybe_unused]] const ConfigValue *value, [[maybe_unused]] int level) const override {return ostr;}

private:
	virtual std::ostream &dump2(std::ostream &ostr, GenericEntry *entry, int level) const;
};

}
