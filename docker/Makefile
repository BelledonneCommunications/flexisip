BASE_NAME=gitlab.linphone.org:4567/bc/public/flexisip
$(eval GIT_DESCRIBE = $(shell sh -c "git describe"))
DOCKER_TAG=$(BASE_NAME):$(GIT_DESCRIBE)
DOCKER_FILE=flex-from-src

# We cannot use dockerfile's COPY outside build context
# we use then flexisip directory as context for flex-from-src instead of docker directory

ifeq ($(DOCKER_FILE), flex-from-src)
  CONTEXT=..
else
  CONTEXT=.
endif

flexisip-build:
	docker build -f $(DOCKER_FILE) --no-cache -t $(DOCKER_TAG) --rm $(CONTEXT)

flexisip-push:
	docker push $(DOCKER_TAG)

flexisip-clean:
	docker image rm $(DOCKER_TAG)

flexisip-deb-before:
	$(eval DOCKER_FILE = flex-from-deb)
	$(eval DOCKER_TAG = $(DOCKER_TAG)-deb)

flexisip-deb-build: flexisip-deb-before flexisip-build

flexisip-deb-push: flexisip-deb-before flexisip-push

flexisip-deb-clean: flexisip-deb-before flexisip-clean

.PHONY: flexisip-build
