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

#include "divertible-fork-entry.hh"

#include "divertible-fork-context.hh"
#include "flexisip/logmanager.hh"
#include "fork.hh"

using namespace std;

namespace flexisip {

DivertibleForkEntry::DivertibleForkEntry(const std::shared_ptr<DivertibleForkContext>& forkContext)
    : mForkContext(forkContext), mLogPrefix(LogManager::makeLogPrefixForInstance(this, string("DivertibleForkEntry"))) {
	LOGD << "Add entry for DivertibleForkContext: " << mForkContext.get();
}

void DivertibleForkEntry::linkForkUnit(const std::shared_ptr<Fork>& fork) {
	mFork = fork;
	LOGD << "Entry is now linked to fork unit: " << fork.get();
}

std::shared_ptr<BranchInfo> DivertibleForkEntry::addBranch(std::unique_ptr<RequestSipEvent>&& ev,
                                                           const std::shared_ptr<ExtendedContact>& contact) {
	auto branch = mForkContext->addBranch(mFork.lock(), std::move(ev), contact);
	if (branch) branch->setForkContext(shared_from_this());
	return branch;
}

void DivertibleForkEntry::start() {
	mForkContext->start(mFork.lock());
}

void DivertibleForkEntry::onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& ev) {
	mForkContext->onResponse(mFork.lock(), br, ev);
}

void DivertibleForkEntry::onNewRegister(const SipUri& dest,
                                        const std::string& uid,
                                        const std::shared_ptr<ExtendedContact>& newContact) {
	mForkContext->onNewRegister(mFork.lock(), dest, uid, newContact);
}

void DivertibleForkEntry::processInternalError(int status, const char* phrase) {
	mForkContext->processInternalError(status, phrase);
}

void DivertibleForkEntry::onCancel(const sofiasip::MsgSip& ms) {
	mForkContext->onCancel(ms);
}

void DivertibleForkEntry::onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept {
	mForkContext->onPushSent(aPNCtx, aRingingPush);
}

bool DivertibleForkEntry::isFinished() const {
	return mForkContext->isFinished();
}
RequestSipEvent& DivertibleForkEntry::getEvent() {
	return mForkContext->getEvent();
}

sofiasip::MsgSipPriority DivertibleForkEntry::getMsgPriority() const {
	return mForkContext->getMsgPriority();
}

const std::shared_ptr<ForkContextConfig>& DivertibleForkEntry::getConfig() const {
	return mForkContext->getConfig();
}

const ForkContext* DivertibleForkEntry::getPtrForEquality() const {
	return this;
}

std::shared_ptr<BranchInfo> DivertibleForkEntry::onDispatchNeeded(const std::shared_ptr<ForkContext>&,
                                                                  const std::shared_ptr<ExtendedContact>& newContact) {
	if (auto listener = mForkContext->getForkContextListener()) {
		return listener->onDispatchNeeded(shared_from_this(), newContact);
	}
	return {};
}

void DivertibleForkEntry::onUselessRegisterNotification(const std::shared_ptr<ForkContext>&,
                                                        const std::shared_ptr<ExtendedContact>& newContact,
                                                        const SipUri& dest,
                                                        const std::string& uid,
                                                        const DispatchStatus reason) {
	if (auto listener = mForkContext->getForkContextListener())
		listener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid, reason);
}

void DivertibleForkEntry::onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) {
	mForkContext->onForkContextFinished(ctx);

	if (auto listener = mForkContext->getForkContextListener()) {
		listener->onForkContextFinished(shared_from_this());
	} else {
		LOGE << "Failed to notify ForkContextListener that fork is finished (std::weak_ptr of listener is empty)";
	}
}

void DivertibleForkEntry::inject(std::unique_ptr<RequestSipEvent>&& event,
                                 const std::shared_ptr<ForkContext>&,
                                 const std::string& contactId) {
	if (auto listener = mForkContext->getInjectorListener())
		listener->inject(std::move(event), shared_from_this(), contactId);
}
} // namespace flexisip