# -*- rpm-spec -*-

%define _prefix    @CMAKE_INSTALL_PREFIX@
%define pkg_prefix @BC_PACKAGE_NAME_PREFIX@

%define build_number @PROJECT_VERSION_BUILD@
%if %{build_number}
%define build_number_ext -%{build_number}
%endif

Name:           @CPACK_PACKAGE_NAME@
Version:        @PROJECT_VERSION@
Release:        %{build_number}%{?dist}
Summary:        JweAuth plugin offers the possibility to use JSON Web Encryption tokens on flexisip

Group:          Security
License:        AGPLv3
URL:            http://flexisip.org
Source0:        %{name}-%{version}%{?build_number_ext}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-buildroot

Requires:      %{pkg_prefix}flexisip
Requires:      %{pkg_prefix}jansson
Requires:      %{pkg_prefix}jose

%description
JweAuth plugin offers the possibility to use JSON Web Encryption tokens on flexisip.

%if 0%{?rhel} && 0%{?rhel} <= 7
%global cmake_name cmake3
%define ctest_name ctest3
%else
%global cmake_name cmake
%define ctest_name ctest
%endif

# This is for debian builds where debug_package has to be manually specified, whereas in centos it does not
%define custom_debug_package %{!?_enable_debug_packages:%debug_package}%{?_enable_debug_package:%{nil}}
%custom_debug_package

%prep
%setup -n %{name}-%{version}%{?build_number_ext}

%build
%{expand:%%%cmake_name} . -DCMAKE_BUILD_TYPE=@CMAKE_BUILD_TYPE@ -DCMAKE_INSTALL_LIBDIR:PATH=%{_libdir} -DCMAKE_PREFIX_PATH:PATH=%{_prefix}
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%check
%{ctest_name} -V %{?_smp_mflags}

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_libdir}/flexisip/plugins/libjweauth.so

%changelog
* Wed Jun 13 2018 ronan.abhamon <ronan.abhamon@belledonne-communications.com>
- Initial RPM release.
