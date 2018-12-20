BASE_NAME=gitlab.linphone.org:4567/bc/public/flexisip
$(eval GIT_DESCRIBE = $(shell sh -c "git describe"))
DOCKER_TAG="$(BASE_NAME):$(GIT_DESCRIBE)"

all: flexisip-build

flexisip-build:
	echo $(DOCKER_TAG)
	docker build -f flex-from-src -t $(DOCKER_TAG) --rm .

flexisip-push:
	docker push $(DOCKER_TAG)

flexisip-clean:
	docker image rm $(DOCKER_TAG)

.PHONY: flexisip-build
