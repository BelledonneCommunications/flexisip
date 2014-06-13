//
//  presence-configmanager.cpp
//  flexisip
//
//  Created by jeh on 07/02/14.
//  Copyright (c) 2014 Belledonne Communications. All rights reserved.
//

#include "presence-configmanager.hh"

static ConfigItemDescriptor global_conf[]={
//	{	Boolean	,	"debug"	        ,	"Outputs very detailed logs",	"false"	},
//	{	String,		"log-filter"	,	"Boost::log filter expression, "
//		"Available attributes include: %Severity% %Module% %callid% %from.uri.user% %from.uri.domain%."
//		"Severity levels are: fatal error info warning debug."
//		"see http://boost-log.sourceforge.net/libs/log1/doc/html/log/detailed/utilities.html#log.detailed.utilities.init.filter_formatter", "%Severity% > debug"},
//	{	Boolean	,	"dump-corefiles",	"Generate a corefile when crashing", "true"},
//	{	Boolean	,	"auto-respawn"  ,	"Automatically respawn flexisip in case of abnormal termination (crashes)",	"true"},
//	{	StringList	,"aliases"	,	"List of white space separated host names pointing to this machine. This is to prevent loops while routing SIP messages.", "localhost"},
	{	StringList	,"transports"	,	"List of white space separated SIP uris where the proxy must listen."
		"Wildcard (0.0.0.0) can be used to mean 'all local ip addresses'. If 'transport' prameter is unspecified, it will listen "
		"to both udp and tcp. An local address to bind can be indicated in the 'maddr' parameter, while the domain part of the uris "
		"are used as public domain or ip address. A per transport directory with the same meaning as tls-certificates-dir can be added as uri parameter.Here some examples to understand:\n"
		"* listen on all local interfaces for udp and tcp, on standart port:\n"
		"\ttransports=sip:0.0.0.0\n"
		"* listen on all local interfaces for udp,tcp and tls, on standart ports:\n"
		"\ttransports=sip:* sips:*\n"
		"* listen on tls localhost with 2 different port and SSL certificates:\n"
		"\ttransports=sip:localhost:5061;tls-certificates-dir=path_a sip:localhost:5062;tls-certificates-dir=path_b,\n"
		"* listen on tls localhost with 2 peer certificate requirements:\n"
		"\ttransports=sip:localhost:5061;require-peer-certificate=0 sip:localhost:5062;require-peer-certificate=1,\n"
		"* listen on 192.168.0.29:6060 with tls, but public hostname is 'sip.linphone.org' used in SIP messages. Bind address won't appear:\n"
		"\ttransports=sips:sip.linphone.org:6060;maddr=192.168.0.29"
		,	"sip:0.0.0.0:5065" },
//	{	String		,"tls-certificates-dir", "Path to the directory where TLS server certificate and private key can be found, concatenated inside an 'agent.pem' file. Any chain certificates must be put into a file named 'cafile.pem'.", "/etc/flexisip/tls"},
//	{	Integer		,"idle-timeout",	"Time interval in seconds after which inactive connections are closed.", "3600"},
//	{	Boolean		,"require-peer-certificate",	"Require client certificate from peer.", "false"},
//	{	Boolean		,"enable-event-logs",	"Enable event logs. Event logs contain per domain and user information about processed registrations, calls and messages.", "false"},
//	{	String		,"event-logs-dir",	"Directory where event logs are written.",	"/var/log/flexisip"},
//	{	Integer		,"transaction-timeout",	"SIP transaction timeout in milliseconds. It is T1*64 (32000 ms) by default.","32000"},
	{	Integer		,"expires",	"Publish default expires in second.  by default.","600"},
	config_item_end
};

PresenceConfigManager::PresenceConfigManager() : GenericManager("flexisip-presence","This is the default Flexisip Presence Server configuration file",{2,3,6,1,4,1,company_id}) {

	GenericStruct *global=new GenericStruct("presence-global","Some global settings of the flexisip presence server.",2);
	getRoot()->addChild(global);
	global->addChildrenValues(global_conf);
	global->setConfigListener(this);
	
	ConfigString *version=new ConfigString("version-number", "Flexisip presence server version.", PACKAGE_VERSION, 999);
	version->setReadOnly(true);
	version->setExportToConfigFile(false);
	global->addChild(version);
	
	ConfigValue *runtimeError=new ConfigRuntimeError("runtime-error", "Retrieve current runtime error state", 998,*getRoot());
	runtimeError->setExportToConfigFile(false);
	runtimeError->setReadOnly(true);
	global->addChild(runtimeError);
	
}
