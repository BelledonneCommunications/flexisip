/*
 * etag-manager.hh
 *
 *  Created on: 13 juin 2014
 *      Author: jehanmonnier
 */

#ifndef ETAG_MANAGER_HH_
#define ETAG_MANAGER_HH_
#include "string"
#include "flexisip-exception.hh"
namespace flexisip {
class EtagManager {

public:
	virtual void invalidateETag(string eTag) = 0;
	virtual void modifyEtag(string oldEtag, string newEtag) throw (FlexisipException)=0;
};
}
#endif /* ETAG_MANAGER_HH_ */
