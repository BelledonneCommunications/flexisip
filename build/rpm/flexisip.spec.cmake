# -*- rpm-spec -*-

%define _prefix    @CMAKE_INSTALL_PREFIX@
%define pkg_prefix @BC_PACKAGE_NAME_PREFIX@
%define package_name @CPACK_PACKAGE_NAME@-${FULL_VERSION}

# re-define some directories for older RPMBuild versions which don't. This messes up the doc/ dir
# taken from https://fedoraproject.org/wiki/Packaging:RPMMacros?rd=Packaging/RPMMacros
%define _datarootdir       %{_prefix}/share
%define _datadir           %{_datarootdir}
%define _docdir            %{_datadir}/doc
%define logdir             %{_localstatedir}/log
%define flexisip_logdir    %{logdir}/flexisip

# Hack: force _mandir to its default value because cmake-builder re-define it
# on rpmbuild invokation with a bad value.
# Remove this hack once Flexisip is based on Linphone SDK >= 4.4
%define _mandir            %{_datarootdir}/man

# to be compliant with RedHat which changed epoch to 1 for an unknown reason
%define epoch     1

%if 0%{?debian_platform}
	%global debian_platform 1
	%global centos_platform 0
%else
	%global debian_platform 0
	%global centos_platform 1
%endif



# Redefiniton of SystemD preun and postun macro for Debian
%if %{debian_platform}

%global systemd_preun() \
if [ "$1" = 'remove' ] ; then \
	systemctl --no-reload disable %*  > /dev/null 2>&1 || : \
	systemctl stop %* > /dev/null 2>&1 || : \
fi

%global systemd_postun \
systemctl daemon-reload >/dev/null 2>&1 || :

%global systemd_postun_with_restart() \
%systemd_postun \
if [ "$1" = 'upgrade' ] ; then \
	systemctl try-restart %*  >/dev/null 2>&1 || : \
fi

%endif # %if %{debian_platform}


%if %{centos_platform}

%global selinux_logdir_context_post \
semanage fcontext -a -t var_log_t '%{logdir}(/.*)?' 2>/dev/null || : \
restorecon -R %{logdir} || :

%global selinux_logdir_context_postun \
if [ $1 -eq 0 ]; then  # final removal \
	semanage fcontext -d -t var_log_t '%{logdir}(/.*)?' 2>/dev/null || : \
fi

%endif # %if %{centos_platform}


Summary:       SIP proxy with media capabilities
Name:          @CPACK_PACKAGE_NAME@
Version:       ${RPM_VERSION}
Release:       ${RPM_RELEASE}%{?dist}
Epoch:         %{epoch}
License:       AGPLv3
Group:         Applications/Communications
URL:           http://flexisip.org
Source0:       %{package_name}.tar.gz
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-buildroot

Requires:      bash >= 2.0
Requires:      at >= 3.1.10
Requires:      %{pkg_prefix}sofia-sip >= 1.13

%if @ENABLE_PROTOBUF@
Requires: protobuf >= 2.3.0
#Requires: protobuf-c >= 0.15
#BuildRequires: protobuf-c-devel >= 0.15
BuildRequires: protobuf-compiler >= 2.3.0
%endif

%if @ENABLE_REDIS@
Requires: %{pkg_prefix}hiredis-devel >= 0.13
%endif

%if @ENABLE_SNMP@
Requires: net-snmp-libs
Requires: net-snmp-devel
%endif

%if @ENABLE_SOCI@
Requires: %{pkg_prefix}soci
Requires: %{pkg_prefix}soci-mysql-devel
%endif

%if @ENABLE_TRANSCODER@
Requires: %{pkg_prefix}mediastreamer
%endif

%if @ENABLE_PRESENCE@
Requires: %{pkg_prefix}belle-sip
%endif

%if @ENABLE_CONFERENCE@
Requires: %{pkg_prefix}liblinphone
%endif

%{systemd_requires}

%if 0%{?rhel} && 0%{?rhel} <= 7
%global cmake_name cmake3
%define ctest_name ctest3
%else
%global cmake_name cmake
%define ctest_name ctest
%endif

%global flexisip_services %(printf 'flexisip-proxy.service'; if [ @ENABLE_PRESENCE@ -eq 1 ]; then printf ' flexisip-presence.service'; fi; if [ @ENABLE_CONFERENCE@ -eq 1 ]; then printf ' flexisip-conference.service'; fi)

%description
Extensible SIP proxy with media capabilities. Designed for robustness and easy of use.

%if @ENABLE_JWE_AUTH_PLUGIN@

%package jwe-auth-plugin
Summary:       JweAuth plugin offers the possibility to use JSON Web Encryption tokens on flexisip
Group:         Security

Requires:      %{name} = %{epoch}:%{version}-%{release}
Requires:      %{pkg_prefix}jose
Requires:      jansson

%description jwe-auth-plugin
JweAuth plugin offers the possibility to use JSON Web Encryption tokens on flexisip.

%endif

%if @ENABLE_EXTERNAL_AUTH_PLUGIN@

%package external-auth-plugin
Summary:       Add the ability to delegate authentication process to an external HTTP server
Group:         Security

Requires:      %{name} = %{epoch}:%{version}-%{release}

%description external-auth-plugin
Add the ability to delegate authentication process to an external HTTP server.

%endif


%prep
%setup -n %{package_name}

%build
%{expand:%%%cmake_name} . -DCMAKE_BUILD_TYPE=@CMAKE_BUILD_TYPE@ -DCMAKE_PREFIX_PATH:PATH=%{_prefix} -DSYSCONF_INSTALL_DIR:PATH=%{_sysconfdir} @RPM_ALL_CMAKE_OPTIONS@


make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

# Mark all libraries as executable because CMake doesn't on
# Debian to be complient with Debian policy. But rpmbuild
# won't strip libraries that aren't marked as executable.
find %{buildroot} -type f -name '*.so.*' -exec chmod -v +x {} \;

#
# Shouldn't be the role of cmake to install all the following stuff ?
# It is surprising to let the specfile install all these things from the source tree.
#
mkdir -p  $RPM_BUILD_ROOT/etc/flexisip
mkdir -p  $RPM_BUILD_ROOT/%{_docdir}
mkdir -p  $RPM_BUILD_ROOT/%{flexisip_logdir}

mkdir -p $RPM_BUILD_ROOT/lib/systemd/system
install -p -m 0644 scripts/flexisip-proxy.service $RPM_BUILD_ROOT/lib/systemd/system
install -p -m 0644 scripts/flexisip-proxy\@.service $RPM_BUILD_ROOT/lib/systemd/system
%if @ENABLE_PRESENCE@
install -p -m 0644 scripts/flexisip-presence.service $RPM_BUILD_ROOT/lib/systemd/system
install -p -m 0644 scripts/flexisip-presence\@.service $RPM_BUILD_ROOT/lib/systemd/system
%endif
%if @ENABLE_CONFERENCE@
	install -p -m 0644 scripts/flexisip-conference.service $RPM_BUILD_ROOT/lib/systemd/system
	install -p -m 0644 scripts/flexisip-conference\@.service $RPM_BUILD_ROOT/lib/systemd/system
%endif
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
install -p -m 0644 scripts/flexisip-logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d

install -p -m 0744 scripts/flexisip_cli.py $RPM_BUILD_ROOT%{_bindir}
install -p -m 0744 scripts/flexisip_monitor.py $RPM_BUILD_ROOT%{_bindir}

%check
%{ctest_name} -V %{?_smp_mflags}

%clean
rm -rf $RPM_BUILD_ROOT

%if %centos_platform
%post
%selinux_logdir_context_post
%systemd_post %flexisip_services
%endif

%preun
%systemd_preun %flexisip_services

%postun
%selinux_logdir_context_postun
%systemd_postun_with_restart %flexisip_services

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_libdir}/*.so
%{_datarootdir}/*
%{_includedir}/flexisip/*.h
%{_includedir}/flexisip/*.hh
%{_includedir}/flexisip/auth/*.hh
%{_includedir}/flexisip/utils/*.hh
%{_includedir}/flexisip/expressionparser-impl.cc
%{_localstatedir}//*

%config(noreplace) /lib/systemd/system/flexisip-proxy.service
%config(noreplace) /lib/systemd/system/flexisip-proxy@.service

%if @ENABLE_PRESENCE@
	%config(noreplace) /lib/systemd/system/flexisip-presence.service
	%config(noreplace) /lib/systemd/system/flexisip-presence@.service
%endif

%if @ENABLE_CONFERENCE@
	%config(noreplace) /lib/systemd/system/flexisip-conference.service
	%config(noreplace) /lib/systemd/system/flexisip-conference@.service
%endif

%{_sysconfdir}/flexisip
%config(noreplace) %{_sysconfdir}/logrotate.d/flexisip-logrotate

%if @ENABLE_JWE_AUTH_PLUGIN@
%files jwe-auth-plugin
%defattr(-,root,root,-)
%{_libdir}/flexisip/plugins/libjweauth.so
%{_libdir}/flexisip/plugins/libjweauth.so.*
%endif

%if @ENABLE_EXTERNAL_AUTH_PLUGIN@
%files external-auth-plugin
%defattr(-,root,root,-)
%{_libdir}/flexisip/plugins/libexternal-auth.so
%{_libdir}/flexisip/plugins/libexternal-auth.so.*
%endif

# This is for Debian build where debug_package has to be manually specified whereas it mustn't on Centos
%define custom_debug_package %{!?_enable_debug_packages:%debug_package}%{?_enable_debug_package:%{nil}}
%custom_debug_package

%changelog

* Wed Jan 16 2019 Sylvain Berfini <sylvain.berfini@belledonne-communications.com>
- Added include directory with flexisip header files

* Tue Nov 27 2018 ronan.abhamon <ronan.abhamon@belledonne-communications.com>
- Do not set CMAKE_INSTALL_LIBDIR and never with _libdir!

* Mon Nov 05 2018 Nicolas Michon <nicolas.michon@belledonne-communications.com>
- Add share directory

* Wed Oct 31 2018 ronan.abhamon <ronan.abhamon@belledonne-communications.com>
- Use epoch in JweAuth plugin requires

* Wed Jun 13 2018 ronan.abhamon <ronan.abhamon@belledonne-communications.com>
- Add JweAuth plugin

* Tue Aug 29  2017 Jehan Monnier <jehan.monnier@linphone.org>
- cmake port

* Fri Dec 02 2016 Simon Morlat <simon.morlat@linphone.org>
- Add init scripts for flexisip-presence

* Thu Jul 28 2016 François Grisez <francois.grisez@belledonne-communications.com>
- Add systemd unit files

* Mon Feb 08 2016 Guillaume Bienkowski <gbi@linphone.org>
- Add soci option

* Wed Nov 04 2015 Sylvain Berfini <sylvain.berfini@linphone.org>
- Add option to disable odb

* Tue Oct 14 2014 Guillaume Bienkowski <gbi@linphone.org>
- Add /opt packaging possibility

* Wed Feb 15 2012 Guillaume Beraudo <guillaume.beraudo@belledonne-communications.com>
- Force use of redhat init script

* Tue Oct 19 2010 Simon Morlat <simon.morlat@belledonne-communications.com>
- Initial specfile for first prototype release
