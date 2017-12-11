# -*- rpm-spec -*-
#
# ack
#
# Default is optimized for Pentium IV but will execute on Pentium II &
# later (i686).

# These 2 lines are here because we can build the RPM for flexisip, in which 
# case we prefix the entire installation so that we don't break compatibility
# with the user's libs.
# To compile with bc prefix, use rpmbuild -ba --with bc [SPEC]
# -*- rpm-spec -*-

## rpmbuild options

# default is to build with redis & protobuf support
%define     redis      %{?_without_redis:0}%{!?_without_redis:1}
%define     protobuf   %{?_without_protobuf:0}%{!?_without_protobuf:1}
%define     push       %{?_with_push:1}%{!?_with_push:0}
%define     transcoder %{?_without_transcoder:0}%{!?_without_transcoder:1}
%define     snmp       %{?_without_snmp:0}%{!?_without_snmp:1}
%define     presence   %{?_with_presence:1}%{!?_with_presence:0}
%define     conference %{?_with_conference:1}%{!?_with_conference:0}
%define     soci       %{?_without_soci:0}%{!?_without_soci:1}

%define     pkg_prefix %{?_with_bc:bc-}%{!?_with_bc:}
%{?_with_bc: %define    _prefix         /opt/belledonne-communications}

# This is for debian builds where debug_package has to be manually specified,
# whereas in centos it does not
%define     flex_debug      %{!?_enable_debug_packages:%debug_package}%{?_enable_debug_package:%{nil}}
# will be 1 if we need to generate a /opt/belledonne-communications RPM
%define     bcpkg      %{?_with_bc:1}%{!?_with_bc:0}

## end rpmbuild options

%define _unpackaged_files_terminate_build 0

# These lines are here because we can build the RPM for flexisip, in which
# case we prefix the entire installation so that we don't break compatibility
# with the user's libs.
# To compile with bc prefix, use rpmbuild -ba --with bc [SPEC]
%define                 pkg_name        %{?_with_bc:bc-flexisip}%{!?_with_bc:flexisip}

# re-define some directories for older RPMBuild versions which don't. This messes up the doc/ dir
# taken from https://fedoraproject.org/wiki/Packaging:RPMMacros?rd=Packaging/RPMMacros
%define _datarootdir       %{_prefix}/share
%define _datadir           %{_datarootdir}
%define _docdir            %{_datadir}/doc

%define build_number @PROJECT_VERSION_BUILD@
Summary:	SIP proxy with media capabilities
Name:		%pkg_name
Version:	@PROJECT_VERSION@
Release:	%build_number%{?dist}
#to be alined with redhat which changed epoc to 1 for an unknown reason
Epoch:		1
License:	GPL
Group:		Applications/Communications
URL:		http://flexisip.org
Source0:	%{name}-%{version}-%build_number.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-buildroot

Requires: bash >= 2.0
Requires: at >= 3.1.10
Requires: %{pkg_prefix}sofia-sip >= 1.13
%if %{protobuf}
Requires: protobuf >= 2.3.0
#Requires: protobuf-c >= 0.15
#BuildRequires: protobuf-c-devel >= 0.15
BuildRequires: protobuf-compiler >= 2.3.0
%endif

%if %{redis}
Requires: %{pkg_prefix}hiredis-devel >= 0.11
%endif

%if %{snmp}
Requires: net-snmp-libs
Requires: net-snmp-devel
%endif

%if %{soci}
Requires: %{pkg_prefix}soci
Requires: %{pkg_prefix}soci-mysql-devel
%endif

%if %{transcoder}
Requires: %{pkg_prefix}mediastreamer
%endif

%if %{presence}
Requires:	%{pkg_prefix}belle-sip
%endif

%if %{conference}
Requires:	%{pkg_prefix}liblinphone
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

%prep
%setup -n %{name}-%{version}-%build_number

%flex_debug

%build
%{expand:%%%cmake_name} . -DCMAKE_INSTALL_LIBDIR:PATH=%{_libdir} -DCMAKE_PREFIX_PATH:PATH=%{_prefix} \
    -DENABLE_REDIS=%{redis} \
    -DENABLE_PROTOBUF=%{protobuf} \
	-DENABLE_SNMP=%{snmp} \
	-DENABLE_SOCI=%{soci} \
	-DENABLE_TRANSCODER=%{transcoder} \
	-DENABLE_PRESENCE=%{presence} \
	-DENABLE_CONFERENCE=%{conference} \
	-DENABLE_PUSHNOTIFICATIN=%{push} \
        -DSYSCONF_INSTALL_DIR:PATH=%{_sysconfdir}


make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

mkdir -p  $RPM_BUILD_ROOT/etc/init.d
mkdir -p  $RPM_BUILD_ROOT/etc/flexisip
mkdir -p  $RPM_BUILD_ROOT/%{_docdir}
mkdir -p  $RPM_BUILD_ROOT/%{_localstatedir}/log/flexisip
%if "0%{?dist}" == "0.deb"
	install -p -m 0744 scripts/debian/flexisip $RPM_BUILD_ROOT%{_sysconfdir}/init.d/flexisip
	%if  %{presence}
		install -p -m 0744 scripts/debian/flexisip-presence $RPM_BUILD_ROOT%{_sysconfdir}/init.d/flexisip-presence
	%endif
%else
	install -p -m 0744 scripts/redhat/flexisip $RPM_BUILD_ROOT%{_sysconfdir}/init.d/flexisip
	%if  %{presence}
		install -p -m 0744 scripts/redhat/flexisip-presence $RPM_BUILD_ROOT%{_sysconfdir}/init.d/flexisip-presence
	%endif
%endif

mkdir -p $RPM_BUILD_ROOT/lib/systemd/system
install -p -m 0644 scripts/flexisip.service $RPM_BUILD_ROOT/lib/systemd/system
install -p -m 0644 scripts/flexisip\@.service $RPM_BUILD_ROOT/lib/systemd/system
%if  %{presence}
	install -p -m 0644 scripts/flexisip-presence.service $RPM_BUILD_ROOT/lib/systemd/system
	install -p -m 0644 scripts/flexisip-presence\@.service $RPM_BUILD_ROOT/lib/systemd/system
%endif
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
install -p -m 0644 scripts/flexisip-logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d

%if %{bcpkg}
export QA_RPATHS=0x0003
%endif

%check
%{ctest_name} -V %{?_smp_mflags}

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [ $1 = 1 ]; then
        /sbin/chkconfig --add flexisip
        /sbin/chkconfig flexisip on
        service flexisip start

%if %{presence}
        /sbin/chkconfig --add flexisip-presence
        /sbin/chkconfig flexisip-presence on
        service flexisip-presence start
%endif
fi

%preun
if [ $1 = 0 ]; then
        service flexisip stop >/dev/null 2>&1 ||:
        /sbin/chkconfig --del flexisip
%if %{presence}
        service flexisip-presence stop >/dev/null 2>&1 ||:
        /sbin/chkconfig --del flexisip-presence
%endif
fi

%postun
if [ "$1" -ge "1" ]; then
        service flexisip condrestart > /dev/null 2>&1 ||:
%if %{presence}
        service flexisip-presence condrestart > /dev/null 2>&1 ||:
%endif
fi

%files
%defattr(-,root,root,-)
%docdir %{_docdir}
%{_docdir}
%{_bindir}/*
%{_libdir}/*

%if %{presence}
	%{_sysconfdir}/init.d/flexisip-presence
	/lib/systemd/system/flexisip-presence.service
	/lib/systemd/system/flexisip-presence@.service
%endif

%{_sysconfdir}/init.d/flexisip
%{_sysconfdir}/flexisip
%{_sysconfdir}/logrotate.d/flexisip-logrotate
/lib/systemd/system/flexisip.service
/lib/systemd/system/flexisip@.service

%changelog
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

