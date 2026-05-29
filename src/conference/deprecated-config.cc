/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/configmanager.hh"

namespace flexisip {

namespace {
// Statically define default configuration items
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        Boolean,
	        "enabled",
	        "Enable conference server", /* Do we need this ? The systemd enablement should be sufficient. */
	        "true",
	    },
	    {
	        String,
	        "transport",
	        "Unique SIP URI on which the server is listening.",
	        "sip:127.0.0.1:6064;transport=tcp",
	    },
	    {
	        StringList,
	        "conference-factory-uris",
	        "List of SIP URIs used by clients to create conferences. This implicitly defines the list of SIP domains "
	        "managed by the conference server. Example:\n"
	        "sip:conference-factory@sip.linphone.org sip:conference-factory@sip.linhome.org",
	        "",
	    },
	    {
	        StringList,
	        "conference-focus-uris",
	        "List of template focus URIs to use when conferences are created through the conference factory.\n"
	        "Focus URIs are unique SIP URIs targeting a specific conference. A 'conf-id' URI parameter providing "
	        "uniqueness is automatically appended at runtime. Example, setting:\n"
	        "conference-focus-uris=sip:conference-focus@sip.linphone.org\n"
	        "instructs the server to generate conference URIs in the form of "
	        "'sip:conference-focus@sip.linphone.org;conf-id=<random string>'\n"
	        "when a client requests to create a conference.",
	        "",
	    },
	    {
	        String,
	        "outbound-proxy",
	        "The SIP proxy URI to which the server will send all outgoing requests.",
	        "sip:127.0.0.1:5060;transport=tcp",
	    },
	    {
	        StringList,
	        "local-domains",
	        "Domains managed by the local SIP service, i.e. domains for which user registration information "
	        "can be found directly in the local registrar database (Redis database).\n"
	        "For external domains (not in this list), a 'reg' SUBSCRIBE (RFC3680) will be emitted. "
	        "It is not necessary to list domains that appear in the 'conference-factory-uris' property. "
	        "They are assumed to be local domains already.\n"
	        "Example: sip.linphone.org conf.linphone.org linhome.org",
	        "",
	    },
	    {
	        IntegerRange,
	        "audio-port",
	        "Audio port to use for RTP and RTCP traffic. You can set a specific port, a range of ports or let the "
	        "server ask the kernel for an available port (special value: 0).\n"
	        "Examples: 'audio-port=0' or 'audio-port=12345' or 'audio-port=1024-65535'",
	        "0",
	    },
	    {
	        IntegerRange,
	        "video-port",
	        "Video port to use for RTP and RTCP traffic. You can set a specific port, a range of ports or let the "
	        "server ask the kernel for an available port (special value: 0).\n"
	        "Examples: 'video-port=0' or 'video-port=12345' or 'video-port=1024-65535'",
	        "0",
	    },
	    {
	        String,
	        "database-backend",
	        "Type of database the server will use to store chat room and conference data. Provided that the required "
	        "Soci modules are installed, the supported databases are: `mysql`, `sqlite3`",
	        "mysql",
	    },
	    {
	        String,
	        "database-connection-string",
	        "Configuration parameters of the database to store chat room and conference data.\n"
	        "The basic format is \"key=value key2=value2\"."
	        "For MySQL, the following is a valid configuration: db='mydb' user='myuser' password='mypass' "
	        "host='myhost.com'.\n"
	        "Please refer to the Soci documentation of your selected backend:\n"
	        "https://soci.sourceforge.net/doc/release/3.2/backends/mysql.html\n"
	        "https://soci.sourceforge.net/doc/release/3.2/backends/sqlite3.html",
	        "db='mydb' user='myuser' password='mypass' host='myhost.com'",
	    },
	    {
	        Boolean,
	        "check-capabilities",
	        "True to make the server check device capabilities before inviting them to a session.\n"
	        "The capability check is currently limited to Linphone clients that put a '+org.linphone.specs' contact "
	        "parameter. This parameter indicates whether they support group chat and secured group chat or not.",
	        "true",
	    },
	    {
	        StringList,
	        "supported-media-types",
	        "List of media types supported by the server.\n"
	        "This allows to specify if this instance is able to provide chat services or audio/video conference "
	        "services, or both.\n"
	        "This parameter cannot be empty.\n"
	        "If 'text' media type is enabled, 'database-connection-string' must be set.\n"
	        "Valid values: 'audio', 'video', 'text'.\n"
	        "Example: audio video text",
	        "text",
	    },
	    {
	        String,
	        "audio-engine-mode",
	        "Valid values: 'mixer', 'semi-sfu', 'sfu'\n"
	        "- 'mixer': The server mixes all relevant streams before sending the final computed stream to "
	        "participants. This mode is quite compute-intensive because it involves several decoding/encoding "
	        "operations.\n"
	        "- 'semi-sfu': The server only forwards relevant streams to participants without any decoding/encoding "
	        "operations. However, RTP headers are re-written by the server.\n"
	        "- 'sfu': The server only forwards relevant streams to participants without any decoding/encoding "
	        "operations and with only slight modifications made to RTP headers. This is the mode required for "
	        "end-to-end encryption.\n",
	        "mixer",
	    },
	    {
	        String,
	        "video-engine-mode",
	        "Valid values: 'semi-sfu', 'sfu'\n"
	        "- 'semi-sfu': The server only forwards relevant streams to participants without any decoding/encoding "
	        "operations. However, RTP headers are re-written by the server.\n"
	        "- 'sfu': The server only forwards relevant streams to participants without any decoding/encoding "
	        "operations and with only slight modifications made to RTP headers. This is the mode required for "
	        "end-to-end encryption.\n",
	        "semi-sfu",
	    },
	    {
	        String,
	        "encryption",
	        "Type of media encryption the server will offer when calling participants to an audio or video "
	        "conference.\n"
	        "Valid values: none, sdes, zrtp, dtls-srtp.",
	        "none",
	    },
	    {
	        StringList,
	        "nat-addresses",
	        "Public host name or IP addresses of the server.\n"
	        "Setting this parameter is required when the conference server is deployed behind a firewall. This way, "
	        "public IP address (v4, v6) can be advertised in SDP, as ICE server-reflexive candidates in order for the "
	        "server to receive RTP media packets from clients.\n"
	        "If no hostname is given, the v4 and v6 IP addresses can be listed, in any order. It is not possible to "
	        "configure several v4 addresses or several v6 addresses.\n"
	        "Examples:\n"
	        "nat-addresses=conference.linphone.org\n"
	        "nat-addresses=5.135.31.160  2001:41d0:303:3aee::1",
	        "",
	    },
	    {
	        Boolean,
	        "empty-chat-room-deletion",
	        "Server shall delete chat rooms that have no registered participants.",
	        "true",
	    },
	    {
	        String,
	        "state-directory",
	        "Directory where the server state files are stored.\n",
	        DEFAULT_LIB_DIR,
	    },
	    {
	        DurationS,
	        "subscription-refresh-delay",
	        "Delay before refreshing external subscriptions to the regevent-server.\n"
	        "It is not recommended to reduce this parameter below 1 minute as refreshing all subscriptions generates "
	        "a significant traffic.",
	        "10min",
	    },
	    {
	        DurationS,
	        "call-timeout",
	        "Server will kill all incoming calls that last longer than the defined value.\n"
	        "Special value 0 disables this feature.",
	        "0",
	    },
	    {
	        DurationS,
	        "no-rtp-timeout",
	        "Duration after which the server will terminate a call if no RTP packets are received from the other call "
	        "participant. For performance reasons, this parameter cannot be disabled.",
	        "30",
	    },
	    {
	        Boolean,
	        "cleanup-expired-conferences",
	        "If enabled, the conference server will periodically remove all expired conferences.",
	        "true",
	    },
	    {
	        DurationS,
	        "conferences-availability-before-start",
	        "Duration used to set how long before the start time of a conference it is possible to join it.",
	        "100y",
	    },
	    {
	        DurationS,
	        "conferences-expiry-time",
	        "Duration after the end of the conference for which it is still possible to join it.\n"
	        "The end of a conference, here, is the latest time between the scheduled end time, and the time when the "
	        "last participant has left.",
	        "30d",
	    },

	    // Deprecated parameters:
	    {
	        Boolean,
	        "enable-one-to-one-chat-room",
	        "Whether one-to-one chat room creation is allowed or not.",
	        "true",
	    },
	    config_item_end,
	};

	auto uS = std::make_unique<GenericStruct>(
	    "conference-server",
	    "Flexisip conference server parameters.\n"
	    "The Flexisip conference server manages group chat and audio/video conferences.\n"
	    "It follows the concepts of RFC4579 for conference establishment and management. Factory and focus URIs must "
	    "be configured.\n"
	    "The server requires a MariaDB/MySQL database in order to store chatroom or conference states (participants "
	    "and their devices).\n"
	    "For chatting capabilities, the server requires a Registrar backend (see section module::Registrar) to "
	    "discover devices (or client instances) of each participant. This requirement creates an explicit dependency "
	    "on the Flexisip proxy server. Please note that this dependency is not required for audio/video "
	    "conferences.\n\n"
	    "ATTENTION. This section of the configuration has no effect anymore. The conference server "
	    "is now part of a different project: 'flexisip-conference'.",
	    0);

	auto* section = root.addChild(std::move(uS));
	section->addChildrenValues(items);
	section->setDeprecated("2026-02-10", "2.6",
	                       "ATTENTION. This section of the configuration has no effect anymore. The conference server "
	                       "is now part of a different project: 'flexisip-conference'.");
});
} // namespace

} // namespace flexisip