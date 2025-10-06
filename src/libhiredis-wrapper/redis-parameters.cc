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

#include "redis-parameters.hh"

#include "async-ctx/factory.hh"
#include "exceptions/bad-configuration.hh"

namespace flexisip::redis::async {

RedisParameters RedisParameters::fromRegistrarConf(GenericStruct const* const registarConf) {
	const auto* connectionParam = registarConf->get<ConfigString>("redis-connection");
	const auto connectionStr = connectionParam->read();
	ConnectionType connection;

	if (!AsyncCtxCreatorFactory::isTlsAllowed() && connectionStr != "tcp") {
		throw BadConfigurationValue{connectionParam,
		                            "unsupported connection type, Flexisip was compiled without 'ENABLE_REDIS_TLS'."};
	}

	if (connectionStr == "tcp") {
		connection = ConnectionType::tcp;
	} else if (connectionStr == "tls-server-auth") {
		connection = ConnectionType::serverSideTls;
	} else if (connectionStr == "tls-mutual") {
		connection = ConnectionType::mutualTls;
	} else {
		throw BadConfigurationValue{connectionParam};
	}

	const auto* certParam = registarConf->get<ConfigString>("redis-tls-certificate");
	const auto* keyParam = registarConf->get<ConfigString>("redis-tls-key");
	const auto* caFileParam = registarConf->get<ConfigString>("redis-tls-cafile");
	const auto tlsCert = certParam->read();
	const auto tlsKey = keyParam->read();
	const auto caFile = caFileParam->read();
	if (connection != ConnectionType::tcp and caFile.empty())
		throw BadConfigurationWithHelp{connectionParam, "if '" + connectionParam->getCompleteName() +
		                                                    "' is not set to 'tcp', '" +
		                                                    caFileParam->getCompleteName() + "' MUST be set."};
	if (connection == ConnectionType::mutualTls and (tlsCert.empty() or tlsKey.empty() or caFile.empty()))
		throw BadConfigurationWithHelp{connectionParam, "if '" + connectionParam->getCompleteName() +
		                                                    "' is enabled, '" + certParam->getCompleteName() + "', '" +
		                                                    keyParam->getCompleteName() + "' and '" +
		                                                    caFileParam->getCompleteName() + "' MUST be set."};

	const ConnectionParameters connectionParams = {
	    .connectionType = connection,
	    .tlsCert = tlsCert,
	    .tlsKey = tlsKey,
	    .tlsCaFile = caFile,
	};

	return RedisParameters{
	    .domain = registarConf->get<ConfigString>("redis-server-domain")->read(),
	    .auth = [&registarConf]() -> decltype(auth) {
		    using namespace redis::auth;

		    const auto& password = registarConf->get<ConfigString>("redis-auth-password")->read();
		    if (password.empty()) {
			    return None();
		    }
		    const auto& user = registarConf->get<ConfigString>("redis-auth-user")->read();
		    if (user.empty()) {
			    return Legacy{password};
		    }
		    return ACL{user, password};
	    }(),
	    .port = registarConf->get<ConfigInt>("redis-server-port")->read(),
	    .mSlaveCheckTimeout = std::chrono::duration_cast<std::chrono::seconds>(
	        registarConf->get<ConfigDuration<std::chrono::seconds>>("redis-slave-check-period")->read()),
	    .useSlavesAsBackup = registarConf->get<ConfigBoolean>("redis-use-slaves-as-backup")->read(),
	    .mSubSessionKeepAliveTimeout =
	        [&registarConf] {
		        auto* param = registarConf->get<ConfigDuration<std::chrono::seconds>>(
		            "redis-subscription-keep-alive-check-period");
		        auto timeout = std::chrono::duration_cast<std::chrono::seconds>(param->read());
		        if (timeout.count() <= 0) throw BadConfigurationValue{param, "parameter must be positive"};
		        return timeout;
	        }(),
	    .connectionParameters = connectionParams,
	};
}

} // namespace flexisip::redis::async