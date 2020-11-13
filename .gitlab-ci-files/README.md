# Flexisip continuous integration

The files contained in this directories are responsible for continuous integration. Each yaml file is included in the root `.gitlab-ci.yml` of the Flexisip project.

## Basic documentation of Gitlab-CI keywords

A basic documentation of the keywords is available in French on the [internal wiki](https://wiki.linphone.org/xwiki/bin/view/Engineering/Fonctionnement%20Gitlab-CI/).
It helps to understand the basics of Gitlab-CI.

## Flexisip tests

The Flexisip tests are run in the `tests-flexisip-mr` job of the `job-linux.yml` file. They rely on the current build from source of the Flexisip docker image done in the `docker-build-flexisip-src` job of the same file.

A Flexisip developper only needs to modify the following variables in `tests-flexisip-mr` for most usages :

- `LIBLINPHONE_DOCKER_TAG`
- `LIME_SERVER_VERSION`
- `ACCOUNT_MANAGER_VERSION`
- `FILE_TRANSFER_SERVER_VERSION`

You can find more information in the comments of this job.

What the test jobs does :

- It creates a workspace to store the logs of all components, and coredumps
- It launches docker-compose, running containers of Flexisip primary and auxiliary services. You can find all the services called in the docker-compose.yaml and docker-compose-standalone.yaml files of the [Flexisip-tester project](https://gitlab.linphone.org/BC/private/flexisip-tester).
- It prints logs of the liblinphone_tester in Gitlab-CI output.
- It uploads other logs in the artifacts.
- It displays the backtrace of liblinphone_tester and flexisip if coredumps were generated during the tests.

## Files structure

The files of this directory are organized by system type and by distribution.
Each file responsible for a Linux distribution has jobs inheriting from jobs located in `job-linux.yml` file.

Typically, this is a sample structure to illustrate :

- job-Linux
  - build
  - test
  - package
  - upload
- job-linux-centos7
  - build-centos7 (extends `build`)
  - test-centos7 (extends `test`)
  - package-centos7 (extends `package`)
  - upload-centos7 (extends `upload`)
- job-linux-ubuntu
  - build-ubuntu (extends `build`)
  - package-ubuntu (extends `package`)
  - upload-ubuntu (extends `upload`)
