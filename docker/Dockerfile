FROM centos
MAINTAINER  Jehan Monnier <jehan.monnier@linphone.org>

# Prepare the Belledonne's repository
COPY docker/Belledonne.repo /etc/yum.repos.d/Belledonne.repo 
RUN yum -y install epel-release  yum-downloadonly gdb
RUN yum update -y

# Download rpm to be able to skip systemd's scripts
RUN yum install -y --downloadonly --downloaddir=/opt bc-flexisip bc-flexisip-debuginfo
RUN mv /opt/bc-flexisip*.rpm /tmp
RUN rpm -i /opt/*.rpm
RUN rpm -i --noscripts /tmp/bc-flexisip*.rpm
#RUN echo '/tmp/core' > /proc/sys/kernel/core_pattern

RUN rm /opt/*.rpm

# Add it to the default path
ENV PATH=$PATH:/opt/belledonne-communications/bin

WORKDIR /opt/belledonne-communications

# Generate a default configuration
RUN flexisip --dump-default all > /etc/flexisip/flexisip.conf

VOLUME /etc/flexisip
COPY docker/flexisip-entrypoint.sh /
COPY docker/backtrace.gdb /
RUN chmod a+x /flexisip-entrypoint.sh

# Script to wait db before launch flexisip [Licence Apache2]
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait
RUN yum clean all

ENTRYPOINT ["/flexisip-entrypoint.sh"]
CMD flexisip
