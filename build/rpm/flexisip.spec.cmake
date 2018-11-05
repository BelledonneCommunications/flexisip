# -*- rpm-spec -*-

%define _prefix    @CMAKE_INSTALL_PREFIX@
%define pkg_prefix @BC_PACKAGE_NAME_PREFIX@

# re-define some directories for older RPMBuild versions which don't. This messes up the doc/ dir
# taken from https://fedoraproject.org/wiki/Packaging:RPMMacros?rd=Packaging/RPMMacros
%define _datarootdir       %{_prefix}/share
%define _datadir           %{_datarootdir}
%define _docdir            %{_datadir}/doc

%define epoch     1

%define build_number @PROJECT_VERSION_BUILD@

Summary:       SIP proxy with media capabilities
Name:          @CPACK_PACKAGE_NAME@
Version:       @PROJECT_VERSION@
Release:       %build_number%{?dist}

#to be alined with redhat which changed epoc to 1 for an unknown reason
Epoch:         %{epoch}
License:       AGPLv3
Group:         Applications/Communications
URL:           http://flexisip.org
Source0:       %{name}-%{version}-%build_number.tar.gz
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

Requires(post): /sbin/chkconfig coreutils
Requires(preun): /sbin/chkconfig /sbin/chkconfig
Requires(postun): /sbin/service


%if 0%{?rhel} && 0%{?rhel} <= 7
%global cmake_name cmake3
%define ctest_name ctest3
%else
%global cmake_name cmake
%define ctest_name ctest
%endif

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

# This is for debian builds where debug_package has to be manually specified, whereas in centos it does not
%define custom_debug_package %{!?_enable_debug_packages:%debug_package}%{?_enable_debug_package:%{nil}}
%custom_debug_package

%prep
%setup -n %{name}-%{version}-%build_number

%build
%{expand:%%%cmake_name} . -DCMAKE_BUILD_TYPE=@CMAKE_BUILD_TYPE@ -DCMAKE_INSTALL_LIBDIR:PATH=%{_libdir} -DCMAKE_PREFIX_PATH:PATH=%{_prefix} -DSYSCONF_INSTALL_DIR:PATH=%{_sysconfdir} @RPM_ALL_CMAKE_OPTIONS@


make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}


#
# Shouldn't be the role of cmake to install all the following stuff ?
# It is surprising to let the specfile install all these things from the source tree.
#
mkdir -p  $RPM_BUILD_ROOT/etc/init.d
mkdir -p  $RPM_BUILD_ROOT/etc/flexisip
mkdir -p  $RPM_BUILD_ROOT/%{_docdir}
mkdir -p  $RPM_BUILD_ROOT/%{_localstatedir}/log/flexisip
%if "0%{?dist}" == "0.deb"
  install -p -m 0744 scripts/debian/flexisip $RPM_BUILD_ROOT%{_sysconfdir}/init.d/flexisip
  %if @ENABLE_PRESENCE@
    install -p -m 0744 scripts/debian/flexisip-presence $RPM_BUILD_ROOT%{_sysconfdir}/init.d/flexisip-presence
  %endif
%else
  install -p -m 0744 scripts/redhat/flexisip $RPM_BUILD_ROOT%{_sysconfdir}/init.d/flexisip
  %if @ENABLE_PRESENCE@
    install -p -m 0744 scripts/redhat/flexisip-presence $RPM_BUILD_ROOT%{_sysconfdir}/init.d/flexisip-presence
  %endif
%endif

mkdir -p $RPM_BUILD_ROOT/lib/systemd/system
install -p -m 0644 scripts/flexisip.service $RPM_BUILD_ROOT/lib/systemd/system
install -p -m 0644 scripts/flexisip\@.service $RPM_BUILD_ROOT/lib/systemd/system
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

%post
if [ $1 = 1 ]; then
  /sbin/chkconfig --add flexisip-proxy
  /sbin/chkconfig flexisip-proxy on
  service flexisip-proxy start

  %if @ENABLE_PRESENCE@
  /sbin/chkconfig --add flexisip-presence
  /sbin/chkconfig flexisip-presence on
  service flexisip-presence start
  %endif
  %if @ENABLE_CONFERENCE@
  /sbin/chkconfig --add flexisip-conference
  /sbin/chkconfig flexisip-conference on
  service flexisip-conference start
  %endif
fi

%preun
if [ $1 = 0 ]; then
  service flexisip-proxy stop >/dev/null 2>&1 ||:
  /sbin/chkconfig --del flexisip-proxy
%if @ENABLE_PRESENCE@
  service flexisip-presence stop >/dev/null 2>&1 ||:
  /sbin/chkconfig --del flexisip-presence
%endif
%if @ENABLE_CONFERENCE@
  service flexisip-conference stop >/dev/null 2>&1 ||:
  /sbin/chkconfig --del flexisip-conference
%endif
fi

%postun
if [ "$1" -ge "1" ]; then
  service flexisip condrestart > /dev/null 2>&1 ||:
%if @ENABLE_PRESENCE@
  service flexisip-presence condrestart > /dev/null 2>&1 ||:
%endif
%if @ENABLE_CONFERENCE@
  service flexisip-conference condrestart > /dev/null 2>&1 ||:
%endif
fi

%files
%defattr(-,root,root,-)
%docdir %{_docdir}
%{_bindir}/*
%{_libdir}/*.so
%{_datarootdir}/*

%if @ENABLE_PRESENCE@
%{_sysconfdir}/init.d/flexisip-presence
/lib/systemd/system/flexisip-presence.service
/lib/systemd/system/flexisip-presence@.service
%endif

%if @ENABLE_CONFERENCE@
	/lib/systemd/system/flexisip-conference.service
	/lib/systemd/system/flexisip-conference@.service
%endif

%{_sysconfdir}/init.d/flexisip
%{_sysconfdir}/flexisip
%{_sysconfdir}/logrotate.d/flexisip-logrotate
/lib/systemd/system/flexisip.service
/lib/systemd/system/flexisip@.service
/lib/systemd/system/flexisip-proxy.service
/lib/systemd/system/flexisip-proxy@.service

%if @ENABLE_JWE_AUTH_PLUGIN@
%files jwe-auth-plugin
%defattr(-,root,root,-)
%{_libdir}/flexisip/plugins/libjweauth.so
%{_libdir}/flexisip/plugins/libjweauth.so.*
%endif

%changelog
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
