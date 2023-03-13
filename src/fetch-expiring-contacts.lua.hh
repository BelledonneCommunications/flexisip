/*  Copyright (C) 2010-2023 Belledonne Communications SARL
    SPDX-License-Identifier: AGPL-3.0-or-later

	You can set your editor to Lua for this file to get syntax highlighting.

	Brief:
		Redis script to return all ExtendedContacts that are about to expire.	
	
	KEYS:
		1: Records to match (usually equal to "fs:*" to match everything)
		   Could arguably be hardcoded, but Redis's doc says a script should
		   declare all the keys it accesses. [string]
		   https://redis.io/docs/manual/programmability/eval-intro/#script-parameterization
	ARGV:
		1: Target time (usually the current time). [Unix timestamp]
		2: Threshold. Only ExtendedContacts that have passed that amount of their
		   lifetime at ARGV[1] will be returned. [ratio between 0.0 and 1.0]
	
	Implementation:
		Loop on all redis keys (Records), then loop on the hash fields 2 by 2 to
		get the ExtendedContacts (skipping the unique ids).
		Parse SIP URI fields and keep contacts above target threshold.
		/!\ Lua string patterns are not POSIX regexps
*/

R"lua(
local all_records = redis.call("KEYS", KEYS[1])
local current_time = tonumber(ARGV[1])
local threshold_ratio = tonumber(ARGV[2])
local expiring_contacts = {}
for _, record in ipairs(all_records) do
	local pairs = redis.call("HGETALL", record)
	for i = 2, #pairs, 2 do
		local contact = pairs[i];
		if not contact:find("pn%-provider=") and not contact:find("pn%-type=") then
			break
		end
		local updatedAt = contact:match("updatedAt=(%d+)")
		if not updatedAt then
			break
		end
		local expires = contact:match("expires=(%d+)")
		if not expires then
			break
		end
		updatedAt, expires = tonumber(updatedAt), tonumber(expires)
		local expiration_time = updatedAt + expires
		local threshold_time = updatedAt + threshold_ratio * expires
		if threshold_time < current_time and current_time < expiration_time then
			table.insert(expiring_contacts, contact)
		end
	end
end
return expiring_contacts
)lua"