//
//  proxy-configmanager.h
//  flexisip
//
//  Created by jeh on 07/02/14.
//  Copyright (c) 2014 Belledonne Communications. All rights reserved.
//

#ifndef __flexisip__proxy_configmanager__
#define __flexisip__proxy_configmanager__

#include "configmanager.hh"

class ProxyConfigManager : public GenericManager {
public:
	static ProxyConfigManager* instance();
	virtual ~ProxyConfigManager(){};
private:
	ProxyConfigManager();
	static ProxyConfigManager* sInstance;
};
#endif /* defined(__flexisip__proxy_configmanager__) */
