# Change Log
All notable changes to this project will be documented in this file.

Group changes to describe their impact on the project, as follows:

    Added for new features.
    Changed for changes in existing functionality.
    Deprecated for once-stable features removed in upcoming releases.
    Removed for deprecated features removed in this release.
    Fixed for any bug fixes.
    Security to invite users to upgrade in case of vulnerabilities.

## [Unreleased]

### [Added]
 - [Presence server] Support of bodyless subscription.
 - [Proxy] Add contextual logs settings
 
### [Changed]
 - [Proxy] log files are now named flexisip-proxy.log, flexisip-conference.log flexisip-presence.log
 - [Proxy] boolean expression engine is faster

### [Fixed]
 - Memory leak (of SIP transactions) in presence server
