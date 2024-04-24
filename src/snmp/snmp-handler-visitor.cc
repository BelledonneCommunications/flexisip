/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024  Belledonne Communications SARL.

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

#include "snmp/snmp-handler-visitor.hh"

namespace flexisip {

void SnmpHandlerVisitor::visitGenericEntry(GenericEntry&) {
	mSnmpErrCode = -1;
}

void SnmpHandlerVisitor::visitConfigRuntimeError(ConfigRuntimeError& entry) {
	if (mReqInfo->mode != MODE_GET) {
		mSnmpErrCode = SNMP_ERR_GENERR;
		return;
	}

	const std::string errors = entry.generateErrors();
	//	LOGD("runtime error handleSnmpRequest %s -> %s", mRegInfo->handlerName, errors.c_str());
	mSnmpErrCode =
	    snmp_set_var_typed_value(mRequests->requestvb, ASN_OCTET_STR, (const u_char*)errors.c_str(), errors.size());
}

void SnmpHandlerVisitor::visitConfigValue(ConfigValue& entry) {
	char* old_value;
	int ret;
	std::string newValue;

	switch (mReqInfo->mode) {
		case MODE_GET:
			//		LOGD("str handleSnmpRequest %s -> %s", mRegInfo->handlerName, get().c_str());
			mSnmpErrCode = snmp_set_var_typed_value(mRequests->requestvb, ASN_OCTET_STR,
			                                        (const u_char*)entry.get().c_str(), entry.get().size());
			return;
		case MODE_SET_RESERVE1:
			ret = netsnmp_check_vb_type(mRequests->requestvb, ASN_OCTET_STR);
			if (ret != SNMP_ERR_NOERROR) {
				netsnmp_set_request_error(mReqInfo, mRequests, ret);
			}

			entry.setNextValue(
			    std::basic_string<char>((char*)mRequests->requestvb->val.string, mRequests->requestvb->val_len));
			if (!entry.onConfigStateChanged(entry, ConfigState::Check)) {
				netsnmp_set_request_error(mReqInfo, mRequests, SNMP_ERR_WRONGVALUE);
			}
			break;
		case MODE_SET_RESERVE2:
			old_value = netsnmp_strdup_and_null((const u_char*)entry.get().c_str(), entry.get().size());
			if (!old_value) {
				netsnmp_set_request_error(mReqInfo, mRequests, SNMP_ERR_RESOURCEUNAVAILABLE);
				return;
			}
			netsnmp_request_add_list_data(mRequests, netsnmp_create_data_list("old_value", old_value, free));
			break;
		case MODE_SET_ACTION:
			newValue.assign((char*)mRequests->requestvb->val.string, mRequests->requestvb->val_len);
			entry.set(newValue);
			entry.onConfigStateChanged(entry, ConfigState::Changed);
			break;
		case MODE_SET_COMMIT:
			//		LOGD("str handleSnmpRequest %s <- %s", mRegInfo->handlerName, get().c_str());
			entry.onConfigStateChanged(entry, ConfigState::Committed);
			break;
		case MODE_SET_FREE:
			// Nothing to do
			break;
		case MODE_SET_UNDO:
			old_value = (char*)netsnmp_request_get_list_data(mRequests, "old_value");
			entry.set(old_value);
			entry.onConfigStateChanged(entry, ConfigState::Reset);
			break;
		default:
			/* we should never get here, so this is a really bad error */
			snmp_log(LOG_ERR, "unknown mode (%d) in handleSnmpRequest\n", mReqInfo->mode);
			mSnmpErrCode = SNMP_ERR_GENERR;
			return;
	}
}

void SnmpHandlerVisitor::visitConfigBoolean(ConfigBoolean& entry) {
	int ret;
	u_short* old_value;
	switch (mReqInfo->mode) {
		case MODE_GET:
			//		LOGD("bool handleSnmpRequest %s -> %d", mRegInfo->handlerName, read()?1:0);
			snmp_set_var_typed_integer(mRequests->requestvb, ASN_INTEGER, entry.read() ? 1 : 0);
			break;
		case MODE_SET_RESERVE1:
			ret = netsnmp_check_vb_int_range(mRequests->requestvb, 0, 1);
			if (ret != SNMP_ERR_NOERROR) {
				netsnmp_set_request_error(mReqInfo, mRequests, ret);
			}
			entry.setNextValue(*mRequests->requestvb->val.integer == 0 ? "0" : "1");
			if (!entry.onConfigStateChanged(entry, ConfigState::Check)) {
				netsnmp_set_request_error(mReqInfo, mRequests, SNMP_ERR_WRONGVALUE);
			}
			break;
		case MODE_SET_RESERVE2:
			old_value = (u_short*)malloc(sizeof(u_short));
			if (!old_value) {
				netsnmp_set_request_error(mReqInfo, mRequests, SNMP_ERR_RESOURCEUNAVAILABLE);
				return;
			}
			*old_value = entry.read() ? 1 : 0;
			netsnmp_request_add_list_data(mRequests, netsnmp_create_data_list("old_value", old_value, free));
			break;
		case MODE_SET_ACTION:
			entry.write(*mRequests->requestvb->val.integer == 1);
			entry.onConfigStateChanged(entry, ConfigState::Changed);
			break;
		case MODE_SET_COMMIT:
			//		LOGD("bool handleSnmpRequest %s <- %d", mRegInfo->handlerName, read()?1:0);
			entry.onConfigStateChanged(entry, ConfigState::Committed);
			break;
		case MODE_SET_FREE:
			// Nothing to do
			break;
		case MODE_SET_UNDO:
			old_value = (u_short*)netsnmp_request_get_list_data(mRequests, "old_value");
			entry.write(*old_value);
			entry.onConfigStateChanged(entry, ConfigState::Reset);
			break;
		default:
			/* we should never get here, so this is a really bad error */
			snmp_log(LOG_ERR, "unknown mode (%d)\n", mReqInfo->mode);
			mSnmpErrCode = SNMP_ERR_GENERR;
			return;
	}
}

void SnmpHandlerVisitor::visitConfigInt(ConfigInt& entry) {
	int* old_value;
	int ret;
	std::ostringstream oss;

	switch (mReqInfo->mode) {
		case MODE_GET:
			//		LOGD("int handleSnmpRequest %s -> %d", mRegInfo->handlerName, read());
			snmp_set_var_typed_integer(mRequests->requestvb, ASN_INTEGER, entry.read());
			break;
		case MODE_SET_RESERVE1:
			ret = netsnmp_check_vb_type(mRequests->requestvb, ASN_INTEGER);
			if (ret != SNMP_ERR_NOERROR) {
				netsnmp_set_request_error(mReqInfo, mRequests, ret);
			}

			oss << *mRequests->requestvb->val.integer;
			entry.setNextValue(oss.str());
			if (!entry.onConfigStateChanged(entry, ConfigState::Check)) {
				netsnmp_set_request_error(mReqInfo, mRequests, SNMP_ERR_WRONGVALUE);
			}
			break;
		case MODE_SET_RESERVE2:
			old_value = (int*)malloc(sizeof(int));
			if (!old_value) {
				netsnmp_set_request_error(mReqInfo, mRequests, SNMP_ERR_RESOURCEUNAVAILABLE);
				return;
			}
			*old_value = entry.read();
			netsnmp_request_add_list_data(mRequests, netsnmp_create_data_list("old_value", old_value, free));
			break;
		case MODE_SET_ACTION:
			// SNMP ensure that the value will have the size of an integer 32.
			entry.write(*mRequests->requestvb->val.integer);
			entry.onConfigStateChanged(entry, ConfigState::Changed);
			break;
		case MODE_SET_COMMIT:
			//		LOGD("int handleSnmpRequest %s <- %d", mRegInfo->handlerName, read());
			entry.onConfigStateChanged(entry, ConfigState::Committed);
			break;
		case MODE_SET_FREE:
			// Nothing to do
			break;
		case MODE_SET_UNDO:
			old_value = (int*)netsnmp_request_get_list_data(mRequests, "old_value");
			entry.write(*old_value);
			entry.onConfigStateChanged(entry, ConfigState::Reset);
			break;
		default:
			/* we should never get here, so this is a really bad error */
			snmp_log(LOG_ERR, "unknown mode (%d)\n", mReqInfo->mode);
			mSnmpErrCode = SNMP_ERR_GENERR;
			return;
	}
}

void SnmpHandlerVisitor::visitStatCounter64(StatCounter64& entry) {
	//	LOGD("counter64 handleSnmpRequest %s -> %lu", mRegInfo->handlerName, read());

	switch (mReqInfo->mode) {
		case MODE_GET: {
			auto entryValue = entry.read();
			struct counter64 counter {
				.high = entryValue >> 32, .low = entryValue & 0x00000000FFFFFFFF
			};
			snmp_set_var_typed_value(mRequests->requestvb, ASN_COUNTER64, (const u_char*)&counter, sizeof(counter));
			break;
		}
		default:
			/* we should never get here, so this is a really bad error */
			snmp_log(LOG_ERR, "unknown mode (%d)\n", mReqInfo->mode);
			mSnmpErrCode = SNMP_ERR_GENERR;
			return;
	}
}

SnmpHandlerVisitor::SnmpHandlerVisitor(netsnmp_agent_request_info* mReqInfo, netsnmp_request_info* mRequests)
    : mReqInfo(mReqInfo), mRequests(mRequests), mSnmpErrCode(SNMP_ERR_NOERROR) {
}

} // namespace flexisip