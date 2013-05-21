# Support for documentation installation
# As the %%doc macro erases the target directory, namely
# $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}, manually installed
# documentation must be saved into a temporary dedicated directory.
%define boost_docdir __tmp_docdir

# Support for long double
%define disable_long_double 0
%ifarch %{arm}
  %define disable_long_double 1
%endif

# Configuration of MPI backends
%ifnarch %{ix86} x86_64
  # No MPICH2 support except on x86 and x86_64
  %bcond_with mpich2
%else
  %bcond_without mpich2
%endif

%ifarch s390 s390x
  # No OpenMPI support on zseries
  %bcond_with openmpi
%else
  %bcond_without openmpi
%endif

Name: boost
Summary: The free peer-reviewed portable C++ source libraries
Version: 1.41.0
Release: 9999%{?dist}
License: Boost
URL: http://sodium.resophonic.com/boost-cmake/%{version}.cmake0/
Group: System Environment/Libraries
%define full_version %{name}-%{version}.cmake0
Source: %{url}/%{full_version}.tar.gz

# From the version 13 of Fedora, the Boost libraries are delivered
# with sonames equal to the Boost version (e.g., 1.41.0).  On older
# versions of Fedora (e.g., Fedora 12), the Boost libraries are
# delivered with another scheme for sonames (e.g., a soname of 5 for
# Fedora 12).  If for some reason you wish to set the sonamever
# yourself, you can do it here.
%define backward_sonamever 5
%if 0%{?rhel}
  %define sonamever %{backward_sonamever}
%else
  %if 0%{?fedora} >= 13
    %define sonamever %{version}
  %else
    %define sonamever %{backward_sonamever}
  %endif
%endif

# boost is an "umbrella" package that pulls in all other boost
# components, except for MPI sub-packages.  Those are "speacial", one
# doesn't necessarily need them and the more typical scenario, I
# think, will be that the developer wants to pick one MPI flavor.
Requires: boost-date-time = %{version}-%{release}
Requires: boost-filesystem = %{version}-%{release}
Requires: boost-graph = %{version}-%{release}
Requires: boost-iostreams = %{version}-%{release}
Requires: boost-program-options = %{version}-%{release}
Requires: boost-python = %{version}-%{release}
Requires: boost-regex = %{version}-%{release}
Requires: boost-serialization = %{version}-%{release}
Requires: boost-signals = %{version}-%{release}
Requires: boost-system = %{version}-%{release}
Requires: boost-test = %{version}-%{release}
Requires: boost-thread = %{version}-%{release}
Requires: boost-wave = %{version}-%{release}
Requires: boost-log = %{version}-%{release}

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: cmake
BuildRequires: libstdc++-devel
BuildRequires: bzip2-libs
BuildRequires: bzip2-devel
BuildRequires: zlib-devel
BuildRequires: python-devel
BuildRequires: libicu-devel
BuildRequires: chrpath

Patch0: boost-cmake-soname.patch
Patch1: boost-graph-compile.patch
Patch2: boost-1.41.0-mapnik.patch
Patch3: boost-1.41.0-shared_ptr_serialization.patch
Patch4: boost-1.41.0-iostreams-zlib.patch

# https://bugzilla.redhat.com/show_bug.cgi?id=905557
# https://svn.boost.org/trac/boost/ticket/6701
Patch5: boost-1.41.0-pool.patch

# https://bugzilla.redhat.com/show_bug.cgi?id=908774
Patch6: boost-1.41.0-exception_ptr.patch

Patch7: boost-log-from-svn.patch
Patch8: boost-log_cmake_rules.patch

%bcond_with tests
%bcond_with docs_generated

%description
Boost provides free peer-reviewed portable C++ source libraries.  The
emphasis is on libraries which work well with the C++ Standard
Library, in the hopes of establishing "existing practice" for
extensions and providing reference implementations so that the Boost
libraries are suitable for eventual standardization. (Some of the
libraries have already been proposed for inclusion in the C++
Standards Committee's upcoming C++ Standard Library Technical Report.)

%package log
Summary: Runtime component of boost date-time library
Group: System Environment/Libraries
Requires: boost-system = %{version}-%{release}
Requires: boost-regex = %{version}-%{release}
Requires: boost-date-time = %{version}-%{release}
Requires: boost-filesystem = %{version}-%{release}
Requires: boost-system = %{version}-%{release}
Requires: boost-thread = %{version}-%{release}
 
%description log


%package date-time
Summary: Runtime component of boost date-time library
Group: System Environment/Libraries

%description date-time

Runtime support for Boost Date Time, set of date-time libraries based
on generic programming concepts.

%package filesystem
Summary: Runtime component of boost filesystem library
Group: System Environment/Libraries
Requires: boost-system = %{version}-%{release}

%description filesystem

Runtime support for the Boost Filesystem Library, which provides
portable facilities to query and manipulate paths, files, and
directories.

%package graph
Summary: Runtime component of boost graph library
Group: System Environment/Libraries
# boost::graph depends on boost::regex for reading graphviz files.
Requires: boost-regex = %{version}-%{release}

%description graph

Runtime support for the BGL graph library.  BGL interface and graph
components are generic, in the same sense as the the Standard Template
Library (STL).

%package iostreams
Summary: Runtime component of boost iostreams library
Group: System Environment/Libraries

%description iostreams

Runtime support for Boost.IOStreams, a framework for defining streams,
stream buffers and i/o filters.

%package math
Summary: Stub that used to contain boost math library
Group: System Environment/Libraries

%description math

This package is a stub that used to contain runtime component of boost
math library.  Now that boost math library is header-only, this
package is empty.  It's kept around only so that during yum-assisted
update, old libraries from boost-math package aren't left around.

%package program-options
Summary:  Runtime component of boost program_options library
Group: System Environment/Libraries

%description program-options

Runtime support of boost program options library, which allows program
developers to obtain (name, value) pairs from the user, via
conventional methods such as command line and configuration file.

%package python
Summary: Runtime component of boost python library
Group: System Environment/Libraries

%description python

The Boost Python Library is a framework for interfacing Python and
C++. It allows you to quickly and seamlessly expose C++ classes
functions and objects to Python, and vice versa, using no special
tools -- just your C++ compiler.  This package contains runtime
support for Boost Python Library.

%package regex
Summary: Runtime component of boost regular expression library
Group: System Environment/Libraries

%description regex

Runtime support for boost regular expression library.

%package serialization
Summary: Runtime component of boost serialization library
Group: System Environment/Libraries

%description serialization

Runtime support for serialization for persistence and marshaling.

%package signals
Summary: Runtime component of boost signals and slots library
Group: System Environment/Libraries

%description signals

Runtime support for managed signals & slots callback implementation.

%package system
Summary: Runtime component of boost system support library
Group: System Environment/Libraries

%description system

Runtime component of Boost operating system support library, including
the diagnostics support that will be part of the C++0x standard
library.

%package test
Summary: Runtime component of boost test library
Group: System Environment/Libraries

%description test

Runtime support for simple program testing, full unit testing, and for
program execution monitoring.

%package thread
Summary: Runtime component of boost thread library
Group: System Environment/Libraries

%description thread

Runtime component Boost.Thread library, which provides classes and
functions for managing multiple threads of execution, and for
synchronizing data between the threads or providing separate copies of
data specific to individual threads.

%package wave
Summary: Runtime component of boost C99/C++ preprocessing library
Group: System Environment/Libraries
Requires: boost-date-time = %{version}-%{release}
Requires: boost-filesystem = %{version}-%{release}
Requires: boost-system = %{version}-%{release}
Requires: boost-thread = %{version}-%{release}

%description wave

Runtime support for the Boost.Wave library, a Standards conformant,
and highly configurable implementation of the mandated C99/C++
preprocessor functionality.

%package devel
Summary: The Boost C++ headers and shared development libraries
Group: Development/Libraries
Requires: boost = %{version}-%{release}
Provides: boost-python-devel = %{version}-%{release}

%description devel
Headers and shared object symlinks for the Boost C++ libraries.

%package static
Summary: The Boost C++ static development libraries
Group: Development/Libraries
Requires: boost-devel = %{version}-%{release}
Obsoletes: boost-devel-static < 1.34.1-14
Provides: boost-devel-static = %{version}-%{release}

%description static
Static Boost C++ libraries.

%package doc
Summary: HTML documentation for the Boost C++ libraries
Group: Documentation
%if 0%{?fedora} >= 10
BuildArch: noarch
%endif
Provides: boost-python-docs = %{version}-%{release}

%description doc
This package contains the documentation in the HTML format of the Boost C++
libraries. The documentation provides the same content as that on the Boost
web page (http://www.boost.org/doc/libs/1_40_0).


%if %{with openmpi}

%package openmpi
Summary: Runtime component of Boost.MPI library
Group: System Environment/Libraries
Requires: openmpi
BuildRequires: openmpi-devel
Requires: boost-serialization = %{version}-%{release}

%description openmpi

Runtime support for Boost.MPI-OpenMPI, a library providing a clean C++
API over the OpenMPI implementation of MPI.

%package openmpi-devel
Summary: Shared library symlinks for Boost.MPI
Group: System Environment/Libraries
Requires: boost-devel = %{version}-%{release}
Requires: boost-openmpi = %{version}-%{release}
Requires: boost-openmpi-python = %{version}-%{release}
Requires: boost-graph-openmpi = %{version}-%{release}

%description openmpi-devel

Devel package for Boost.MPI-OpenMPI, a library providing a clean C++
API over the OpenMPI implementation of MPI.

%package openmpi-python
Summary: Python runtime component of Boost.MPI library
Group: System Environment/Libraries
Requires: boost-openmpi = %{version}-%{release}
Requires: boost-python = %{version}-%{release}
Requires: boost-serialization = %{version}-%{release}

%description openmpi-python

Python support for Boost.MPI-OpenMPI, a library providing a clean C++
API over the OpenMPI implementation of MPI.

%package graph-openmpi
Summary: Runtime component of parallel boost graph library
Group: System Environment/Libraries
Requires: boost-openmpi = %{version}-%{release}
Requires: boost-serialization = %{version}-%{release}

%description graph-openmpi

Runtime support for the Parallel BGL graph library.  The interface and
graph components are generic, in the same sense as the the Standard
Template Library (STL).  This libraries in this package use OpenMPI
backend to do the parallel work.

%endif


%if %{with mpich2}

%package mpich2
Summary: Runtime component of Boost.MPI library
Group: System Environment/Libraries
Requires: mpich2
BuildRequires: mpich2-devel
Requires: boost-serialization = %{version}-%{release}

%description mpich2

Runtime support for Boost.MPI-MPICH2, a library providing a clean C++
API over the MPICH2 implementation of MPI.

%package mpich2-devel
Summary: Shared library symlinks for Boost.MPI
Group: System Environment/Libraries
Requires: boost-devel = %{version}-%{release}
Requires: boost-mpich2 = %{version}-%{release}
Requires: boost-mpich2-python = %{version}-%{release}
Requires: boost-graph-mpich2 = %{version}-%{release}

%description mpich2-devel

Devel package for Boost.MPI-MPICH2, a library providing a clean C++
API over the MPICH2 implementation of MPI.

%package mpich2-python
Summary: Python runtime component of Boost.MPI library
Group: System Environment/Libraries
Requires: boost-mpich2 = %{version}-%{release}
Requires: boost-python = %{version}-%{release}
Requires: boost-serialization = %{version}-%{release}

%description mpich2-python

Python support for Boost.MPI-MPICH2, a library providing a clean C++
API over the MPICH2 implementation of MPI.

%package graph-mpich2
Summary: Runtime component of parallel boost graph library
Group: System Environment/Libraries
Requires: boost-mpich2 = %{version}-%{release}
Requires: boost-serialization = %{version}-%{release}

%description graph-mpich2

Runtime support for the Parallel BGL graph library.  The interface and
graph components are generic, in the same sense as the the Standard
Template Library (STL).  This libraries in this package use MPICH2
backend to do the parallel work.

%endif


%prep
%setup -q -n %{full_version}

sed 's/_FEDORA_SONAME/%{sonamever}/' %{PATCH0} | %{__patch} -p0 --fuzz=0
%patch1 -p0
%patch2 -p0
%patch3 -p1
%patch4 -p2
%patch5 -p1
%patch6 -p0
%patch7 -p0
%patch8 -p1

%build
# Support for building tests.
%define boost_testflags -DBUILD_TESTS="NONE"
%if %{with tests}
  %define boost_testflags -DBUILD_TESTS="ALL"
%endif

export CXXFLAGS="-fno-strict-aliasing %{optflags}"

( echo ============================= build serial ==================
  mkdir serial
  cd serial
  %cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo %{boost_testflags} \
         -DENABLE_SINGLE_THREADED=YES -DINSTALL_VERSIONED=OFF \
         -DWITH_MPI=OFF ..
  make VERBOSE=1 %{?_smp_mflags}
)

# Build MPI parts of Boost with OpenMPI support
%if %{with openmpi}
%{_openmpi_load}
# Work around the bug: https://bugzilla.redhat.com/show_bug.cgi?id=560224
MPI_COMPILER=openmpi-%{_arch}
export MPI_COMPILER
( echo ============================= build $MPI_COMPILER ==================
  mkdir $MPI_COMPILER
  cd $MPI_COMPILER
  %cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo %{boost_testflags} \
         -DENABLE_SINGLE_THREADED=YES -DINSTALL_VERSIONED=OFF \
         -DBUILD_PROJECTS="serialization;python;mpi;graph_parallel" \
         -DBOOST_LIB_INSTALL_DIR=$MPI_LIB ..
  make VERBOSE=1 %{?_smp_mflags}
)
%{_openmpi_unload}
%endif

# Build MPI parts of Boost with MPICH2 support
%if %{with mpich2}
%{_mpich2_load}
( echo ============================= build $MPI_COMPILER ==================
  mkdir $MPI_COMPILER
  cd $MPI_COMPILER
  %cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo %{boost_testflags} \
         -DENABLE_SINGLE_THREADED=YES -DINSTALL_VERSIONED=OFF \
         -DBUILD_PROJECTS="serialization;python;mpi;graph_parallel" \
         -DBOOST_LIB_INSTALL_DIR=$MPI_LIB ..
  make VERBOSE=1 %{?_smp_mflags}
)
%{_mpich2_unload}
%endif


%check
%if %{with tests}
cd build

# Standard test with CMake, depends on installed boost-test.
ctest --verbose --output-log testing.log
if [ -f testing.log ]; then
  echo "" >> testing.log
  echo `date` >> testing.log
  echo "" >> testing.log
  echo `uname -a` >> testing.log
  echo "" >> testing.log
  echo `g++ --version` >> testing.log
  echo "" >> testing.log
  testdate=`date +%Y%m%d`
  testarch=`uname -m`
  email=benjamin.kosnik@gmail.com
  bzip2 -f testing.log
  echo "sending results starting"
  echo | mutt -s "$testdate boost test $testarch" -a testing.log.bz2 $email
  echo "sending results finished"
else
  echo "error with results"
fi
cd %{_builddir}/%{full_version}
%endif


%install
%{__rm} -rf $RPM_BUILD_ROOT

cd %{_builddir}/%{full_version}/

%if %{with openmpi}
%{_openmpi_load}
# Work around the bug: https://bugzilla.redhat.com/show_bug.cgi?id=560224
MPI_COMPILER=openmpi-%{_arch}
export MPI_COMPILER
echo ============================= install $MPI_COMPILER ==================
DESTDIR=$RPM_BUILD_ROOT make -C $MPI_COMPILER VERBOSE=1 install
# Remove parts of boost that we don't want installed in MPI directory.
%{__rm} -f $RPM_BUILD_ROOT/$MPI_LIB/libboost_{python,{w,}serialization}*
# Suppress the mpi.so python module, as it not currently properly
# generated (some dependencies are missing. It is temporary until
# upstream Boost-CMake fixes that (see
# http://lists.boost.org/boost-cmake/2009/12/0859.php for more
# details)
%{__rm} -f $RPM_BUILD_ROOT/$MPI_LIB/mpi.so
# Kill any debug library versions that may show up un-invited.
%{__rm} -f $RPM_BUILD_ROOT/$MPI_LIB/*-d.*
# Remove cmake configuration files used to build the Boost libraries
find $RPM_BUILD_ROOT/$MPI_LIB -name '*.cmake' -exec %{__rm} -f {} \;
%{_openmpi_unload}
%endif

%if %{with mpich2}
%{_mpich2_load}
echo ============================= install $MPI_COMPILER ==================
DESTDIR=$RPM_BUILD_ROOT make -C $MPI_COMPILER VERBOSE=1 install
# Remove parts of boost that we don't want installed in MPI directory.
%{__rm} -f $RPM_BUILD_ROOT/$MPI_LIB/libboost_{python,{w,}serialization}*
# Suppress the mpi.so python module, as it not currently properly
# generated (some dependencies are missing. It is temporary until
# upstream Boost-CMake fixes that (see
# http://lists.boost.org/boost-cmake/2009/12/0859.php for more
# details)
%{__rm} -f $RPM_BUILD_ROOT/$MPI_LIB/mpi.so
# Kill any debug library versions that may show up un-invited.
%{__rm} -f $RPM_BUILD_ROOT/$MPI_LIB/*-d.*
# Remove cmake configuration files used to build the Boost libraries
find $RPM_BUILD_ROOT/$MPI_LIB -name '*.cmake' -exec %{__rm} -f {} \;
%{_mpich2_unload}
%endif

echo ============================= install serial ==================
DESTDIR=$RPM_BUILD_ROOT make -C serial VERBOSE=1 install
# Kill any debug library versions that may show up un-invited.
%{__rm} -f $RPM_BUILD_ROOT/%{_libdir}/*-d.*

# Prepare the place to temporary store the generated documentation
%{__rm} -rf %{boost_docdir} && %{__mkdir_p} %{boost_docdir}/html

# Install documentation files (HTML pages) within the temporary place
cd %{_builddir}/%{full_version}
DOCPATH=%{boost_docdir}
find libs doc more -type f \( -name \*.htm -o -name \*.html \) \
    | sed -n '/\//{s,/[^/]*$,,;p}' \
    | sort -u > tmp-doc-directories
sed "s:^:$DOCPATH/:" tmp-doc-directories \
    | xargs --no-run-if-empty %{__install} -d
cat tmp-doc-directories | while read tobeinstalleddocdir; do
    find $tobeinstalleddocdir -mindepth 1 -maxdepth 1 -name \*.htm\* \
    | xargs %{__install} -p -m 644 -t $DOCPATH/$tobeinstalleddocdir
done
%{__rm} -f tmp-doc-directories
%{__install} -p -m 644 -t $DOCPATH LICENSE_1_0.txt index.htm index.html

# Remove scripts used to generate include files
find $RPM_BUILD_ROOT%{_includedir}/ \( -name '*.pl' -o -name '*.sh' \) -exec %{__rm} -f {} \;

# The cmake files installed in /usr/share cause multilib conflicts.
# Install them in /usr/lib{,64} instead.
%{__rm} -Rf $RPM_BUILD_ROOT%{_datadir}/%{name}-%{version}/cmake
%{__install} -d $RPM_BUILD_ROOT/%{_libdir}/boost
%{__install} -p -m 644 -t $RPM_BUILD_ROOT/%{_libdir}/boost \
	     ./serial/CMakeFiles/BoostConfig.cmake \
	     ./serial/CMakeFiles/BoostConfigVersion.cmake
# Also put there the files that are now in libdir, so that it's all in
# one place
find $RPM_BUILD_ROOT/%{_libdir} -name '*.cmake' \
     -exec %{__mv} {} $RPM_BUILD_ROOT/%{_libdir}/boost/ \;
# And adjust the include path in BoostConfig.cmake
sed -i '/^include/s,"\(.*\)\(/Boost.cmake\)","\1/boost\2",' \
    $RPM_BUILD_ROOT/%{_libdir}/boost/BoostConfig.cmake


%clean
%{__rm} -rf $RPM_BUILD_ROOT


# MPI subpackages don't need the ldconfig magic.  They are hidden by
# default, in MPI backend-specific directory, and only show to the
# user after the relevant environment module has been loaded.

%post date-time -p /sbin/ldconfig

%postun date-time -p /sbin/ldconfig

%post filesystem -p /sbin/ldconfig

%postun filesystem -p /sbin/ldconfig

%post graph -p /sbin/ldconfig

%postun graph -p /sbin/ldconfig

%post iostreams -p /sbin/ldconfig

%postun iostreams -p /sbin/ldconfig

%post program-options -p /sbin/ldconfig

%postun program-options -p /sbin/ldconfig

%post python -p /sbin/ldconfig

%postun python -p /sbin/ldconfig

%post regex -p /sbin/ldconfig

%postun regex -p /sbin/ldconfig

%post serialization -p /sbin/ldconfig

%postun serialization -p /sbin/ldconfig

%post signals -p /sbin/ldconfig

%postun signals -p /sbin/ldconfig

%post system -p /sbin/ldconfig

%postun system -p /sbin/ldconfig

%post test -p /sbin/ldconfig

%postun test -p /sbin/ldconfig

%post thread -p /sbin/ldconfig

%postun thread -p /sbin/ldconfig

%post wave -p /sbin/ldconfig

%postun wave -p /sbin/ldconfig

%post log -p /sbin/ldconfig
 
%postun log -p /sbin/ldconfig
 


%files

%files log
%defattr(-, root, root, -)
%{_libdir}/libboost_log*.so.%{sonamever}
 
%files date-time
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_date_time*.so.%{sonamever}

%files filesystem
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_filesystem*.so.%{sonamever}

%files graph
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_graph.so.%{sonamever}
%{_libdir}/libboost_graph-mt.so.%{sonamever}

%files iostreams
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_iostreams*.so.%{sonamever}

%files math

%files test
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_prg_exec_monitor*.so.%{sonamever}
%{_libdir}/libboost_unit_test_framework*.so.%{sonamever}

%files program-options
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_program_options*.so.%{sonamever}

%files python
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_python*.so.%{sonamever}

%files regex
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_regex*.so.%{sonamever}

%files serialization
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_serialization*.so.%{sonamever}
%{_libdir}/libboost_wserialization*.so.%{sonamever}

%files signals
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_signals*.so.%{sonamever}

%files system
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_system*.so.%{sonamever}

%files thread
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_thread*.so.%{sonamever}

%files wave
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/libboost_wave*.so.%{sonamever}

%files doc
%defattr(-, root, root, -)
%doc %{boost_docdir}/*

%files devel
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_includedir}/%{name}
%{_libdir}/libboost_*.so
%{_datadir}/%{name}-%{version}
%{_libdir}/boost/Boost*.cmake

%files static
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/*.a
%if %{with mpich2}
%{_libdir}/mpich2/lib/*.a
%endif
%if %{with openmpi}
%{_libdir}/openmpi/lib/*.a
%endif

# OpenMPI packages
%if %{with openmpi}

%files openmpi
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/openmpi/lib/libboost_mpi.so.%{sonamever}
%{_libdir}/openmpi/lib/libboost_mpi-mt.so.%{sonamever}

%files openmpi-devel
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/openmpi/lib/libboost_*.so

%files openmpi-python
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/openmpi/lib/libboost_mpi_python*.so.%{sonamever}

%files graph-openmpi
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/openmpi/lib/libboost_graph_parallel.so.%{sonamever}
%{_libdir}/openmpi/lib/libboost_graph_parallel-mt.so.%{sonamever}

%endif

# MPICH2 packages
%if %{with mpich2}

%files mpich2
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/mpich2/lib/libboost_mpi.so.%{sonamever}
%{_libdir}/mpich2/lib/libboost_mpi-mt.so.%{sonamever}

%files mpich2-devel
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/mpich2/lib/libboost_*.so

%files mpich2-python
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/mpich2/lib/libboost_mpi_python*.so.%{sonamever}

%files graph-mpich2
%defattr(-, root, root, -)
%doc LICENSE_1_0.txt
%{_libdir}/mpich2/lib/libboost_graph_parallel.so.%{sonamever}
%{_libdir}/mpich2/lib/libboost_graph_parallel-mt.so.%{sonamever}

%endif

%changelog
* Thu Mar 14 2013 Petr Machata <pmachata@redhat.com> - 1.41.0-17
- Add in explicit dependence between boost-*mpich2* and
  boost-serialization.

* Wed Mar 13 2013 Petr Machata <pmachata@redhat.com> - 1.41.0-16
- Fix a GCC warning for looser throw specifier in
  boost::exception_ptr::~exception_ptr.
  (boost-1.41.0-exception_ptr.patch)

* Thu Mar  7 2013 Petr Machata <pmachata@redhat.com> - 1.41.0-15
- Add in explicit dependences between some boost subpackages

* Thu Mar  7 2013 Petr Machata <pmachata@redhat.com> - 1.41.0-14
- Build with -fno-strict-aliasing

* Tue Feb 12 2013 Petr Machata <pmachata@redhat.com> - 1.41.0-13
- In Boost.Pool, be careful not to overflow allocated chunk size
  (boost-1.41.0-pool.patch)

* Tue Jul 19 2011 Petr Machata <pmachata@redhat.com> - 1.41.0-12
- Add an upstream patch that fixes computation of CRC in zlib streams.
- Resolves: #707624

* Tue May 25 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-11
- ... and revert the soname change, because that's not the smartest
  thing to do mid-release.
- Resolves: #594146

* Fri May 21 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-10
- Turn on OpenMPI support on non-s390 arches.  It was accidentally
  turned off everywhere.
- Move cmake files to libdir to avoid multilib conflicts.
- Also install Boost.cmake, which is included by BoostConfig.cmake
- Change soname selection to work on RHELs.
- Resolves: #586204
- Resolves: #592516
- Resolves: #594146

* Thu Mar 18 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-9
- Use a .gz archive instead of bz2, because that's what's hosted now.
  Fill in the full URL.
- Resolves: #571607

* Tue Mar 16 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-8
- Import 1.41.1 with fixes from Fedora 13 to RHEL 6
- Turn off OpenMPI support on s390*, which isn't available in RHEL 6
- Resolves: #571607

* Mon Feb 22 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-7
- Add a patch for serialization of shared pointers to non polymorphic
  types

* Tue Feb  2 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-6
- More subpackage interdependency adjustments
  - boost doesn't bring in the MPI stuff.  Instead, $MPI-devel does.
    It needs to, so that the symlinks don't dangle.
  - boost-graph-$MPI depends on boost-$MPI so that boost-mpich2
    doesn't satisfy the SONAME dependency of boost-graph-openmpi.

* Mon Feb  1 2010 Denis Arnaud <denis.arnaud_fedora@m4x.org> - 1.41.0-5
- Various fixes on the specification

* Fri Jan 29 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-5
- Introduce support for both OpenMPI and MPICH2

* Mon Jan 25 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-4
- Add a patch to build mapnik

* Tue Jan 19 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-3
- Generalize the soname selection

* Mon Jan 18 2010 Denis Arnaud <denis.arnaud_fedora@m4x.org> - 1.41.0-2.2
- Further split the Boost.MPI sub-package into boost-mpi and
  boost-mpi-python
- Changed the description of Boost.MPI according to the actual
  dependency (MPICH2 rather than OpenMPI)
- Added a few details on the generation of the mpi.so library

* Thu Jan 14 2010 Petr Machata <pmachata@redhat.com> - 1.41.0-2
- Replace a boost-math subpackage with a stub
- Drop _cmake_lib_suffix and CMAKE_INSTALL_PREFIX magic, the rpm macro
  does that for us
- Drop LICENSE from the umbrella package
- Drop obsolete Obsoletes: boost-python and boost-doc <= 1.30.2

* Tue Jan 12 2010 Benjamin Kosnik <bkoz@redhat.com> - 1.41.0-1
- Don't package generated debug libs, even with 
  (-DCMAKE_BUILD_TYPE=RelWithDebInfo | Release).
- Update and include boost-cmake-soname.patch.
- Uncomment ctest.
- Fix up --with tests to run tests.

* Sat Dec 19 2009 Denis Arnaud <denis.arnaud_fedora@m4x.org> - 1.41.0-0.7
- Switched off the delivery into a versioned sub-directory

* Thu Dec 17 2009 Denis Arnaud <denis.arnaud_fedora@m4x.org> - 1.41.0-0.6
- Boost-CMake upstream integration

* Wed Dec 16 2009 Benjamin Kosnik <bkoz@redhat.com> - 1.41.0-0.5
- Rebase to 1.41.0
- Set build type to RelWithDebInfo

* Mon Nov 16 2009 Denis Arnaud <denis.arnaud_fedora@m4x.org> - 1.40.0-1
- Add support for the Boost.MPI sub-package
- Build with CMake (https://svn.boost.org/trac/boost/wiki/CMake)

* Mon Nov 16 2009 Petr Machata <pmachata@redhat.com> - 1.39.0-11
- Move comment in Patch13 out of line

* Mon Nov 16 2009 Petr Machata <pmachata@redhat.com> - 1.39.0-10
- translate_exception.hpp misses a include
- Related: #537612

* Thu Oct 15 2009 Petr Machata <pmachata@redhat.com> - 1.39.0-9
- Package index.html in the -doc subpackage
- Resolves: #529030

* Wed Oct 14 2009 Petr Machata <pmachata@redhat.com> - 1.39.0-8
- Several fixes to support PySide
- Resolves: #520087
- GCC 4.4 name resolution fixes for GIL
- Resolves: #526834

* Sun Oct 11 2009 Jitesh Shah <jiteshs@marvell.com> 1.39.0-7
- Disable long double support for ARM

* Tue Sep 08 2009 Karsten Hopp <karsten@redhat.com> 1.39.0-6
- bump release and rebuild as the package was linked with an old libicu
  during the mass rebuild on s390x

* Wed Aug 26 2009 Tomas Mraz <tmraz@redhat.com> - 1.39.0-5
- Make it to be usable with openssl-1.0

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.39.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu Jul  2 2009 Petr Machata <pmachata@redhat.com> - 1.39.0-3
- Drop file list for main "boost" package, which was inadvertently left in.
- Add thread sub-package to capture omitted boost_thread.
- Add upstream patch to make boost_filesystem compatible with C++0x.
- Resolves: #496188
- Resolves: #509250

* Mon May 11 2009 Benjamin Kosnik <bkoz@redhat.com> - 1.39.0-2
- Apply patch from Caolan McNamara

* Thu May 07 2009 Benjamin Kosnik <bkoz@redhat.com> - 1.39.0-1
- Update release.

* Wed May 06 2009 Benjamin Kosnik <bkoz@redhat.com> - 1.39.0-0.3
- Fixes for rpmlint.

* Wed May 06 2009 Petr Machata <pmachata@redhat.com> - 1.39.0-0.2
- Split up boost package to sub-packages per library
- Resolves: #496188

* Wed May 06 2009 Benjamin Kosnik <bkoz@redhat.com> - 1.39.0-0.1
- Rebase to 1.39.0.
- Add --with docs_generated.
- #225622: Substitute optflags at prep time instead of RPM_OPT_FLAGS.

* Mon May 04 2009 Benjamin Kosnik <bkoz@redhat.com> - 1.37.0-7
- Rebuild for libicu bump.

* Mon Mar 23 2009 Petr Machata <pmachata@redhat.com> - 1.37.0-6
- Apply a SMP patch from Stefan Ring
- Apply a workaround for "cannot appear in a constant-expression" in
  dynamic_bitset library.
- Resolves: #491537

* Mon Feb 23 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.37.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Mon Jan 12 2009 Petr Machata <pmachata@redhat.com> - 1.37.0-3
- Apply a unneccessary_iostreams patch from Caolan McNamara
- Fix soname patch so that it applies with fuzz=0.  Use fuzz=0 option
  in spec file just like ordinary patches do.
- Resolves: #479409

* Fri Dec 19 2008 Petr Machata <pmachata@redhat.com> - 1.37.0-2
- Apply a function_template patch from Caolan McNamara
- Resolves: #477131

* Tue Dec 16 2008 Benjamin Kosnik <bkoz@redhat.com> - 1.37.0-1
- Fix rpmlint rpath errors.
- Fix rpmlint warnings on tabs and spaces.
- Bump SONAME to 4

* Tue Nov 17 2008 Benjamin Kosnik <bkoz@redhat.com> - 1.37.0-0.1
- Rebase to 1.37.0.

* Tue Oct 21 2008 Benjamin Kosnik <bkoz@redhat.com> - 1.36.0-1
- Rebase to 1.36.0.

* Mon Oct  6 2008 Petr Machata <pmachata@redhat.com> - 1.34.1-17
- Fix gcc43 patch to apply cleanly under --fuzz=0
- Resolves: #465003

* Mon Aug 11 2008 Petr Machata <pmachata@redhat.com> - 1.36.0-0.1.beta1
- Rebase to 1.36.0.beta1
  - Drop boost-regex.patch and portions of boost-gcc43.patch, port the rest
  - Automate SONAME tracking and bump SONAME to 4
  - Adjust boost-configure.patch to include threading=single,multi explicitly

* Thu Jun 12 2008 Petr Machata <pmachata@redhat.com> - 1.34.1-16
- Fix "changes meaning of keywords" in boost date_time
- Related: #450718

* Thu May 29 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 1.34.1-15
- fix license tag

* Thu Mar 27 2008 Petr Machata <pmachata@redhat.com> - 1.34.1-14
- Change devel-static back to static.
- Related: #225622

* Wed Mar 26 2008 Petr Machata <pmachata@redhat.com> - 1.34.1-13
- Install library doc files
- Revamp %%install phase to speed up overall build time
- Some cleanups per merge review
- Resolves: #437032

* Thu Feb 14 2008 Petr Machata <pmachata@redhat.com> - 1.34.1-12
- Fix "changes meaning of keywords" in boost python
- Resolves: #432694

* Wed Feb 13 2008 Petr Machata <pmachata@redhat.com> - 1.34.1-11
- Fix "changes meaning of special_values_parser" in boost date_time
- Resolves: #432433

* Wed Feb  6 2008 Petr Machata <pmachata@redhat.com> - 1.34.1-10
- Fixes for GCC 4.3
- Resolves: #431609

* Mon Jan 14 2008 Benjamin Kosnik <bkoz@redhat.com> 1.34.1-7
- Fixes for boost.regex (rev 42674).

* Wed Sep 19 2007 Benjamin Kosnik <bkoz@redhat.com> 1.34.1-5
- (#283771: Linking against boost libraries fails).

* Tue Aug 21 2007 Benjamin Kosnik <bkoz@redhat.com> 1.34.1-4
- Rebuild.

* Wed Aug 08 2007 Benjamin Kosnik <bkoz@redhat.com> 1.34.1-3
- Rebuild for icu 3.8 bump.

* Thu Aug 02 2007 Benjamin Kosnik <bkoz@redhat.com> 1.34.1-2
- SONAME to 3.

* Tue Jul 31 2007 Benjamin Kosnik <bkoz@redhat.com> 1.34.1-1
- Update to boost_1_34_1.
- Source via http.
- Philipp Thomas <pth.suse.de> fix for RPM_OPT_FLAGS
- Philipp Thomas <pth.suse.de> fix for .so sym links.
- (#225622) Patrice Dumas review comments.

* Tue Jun 26 2007 Benjamin Kosnik <bkoz@redhat.com> 1.34.1.rc1-0.1
- Update to boost_1_34_1_RC1.

* Mon Apr 02 2007 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-13
- (#225622: Merge Review: boost)
  Change static to devel-static.

* Mon Mar 26 2007 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-12
- (#233523: libboost_python needs rebuild against python 2.5)
  Use patch.

* Mon Mar 26 2007 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-11
- (#225622: Merge Review: boost)
  Source to http.
  BuildRoot to preferred value.
  PreReq to post/postun -p
  Clarified BSL as GPL-Compatible, Free Software License.
  Remove Obsoletes.
  Add Provides boost-python.
  Remove mkdir -p $RPM_BUILD_ROOT%%{_docdir}
  Added periods for decription text.
  Fix Group field.
  Remove doc Requires boost.
  Preserve timestamps on install.
  Use %%defattr(-, root, root, -)
  Added static package for .a libs.
  Install static libs with 0644 permissions.
  Use %%doc for doc files.

* Mon Jan 22 2007 Benjamin Kosnik <bkoz@redhat.com> 1.34.0-0.5
- Update to boost.RC_1_34_0 snapshot as of 2007-01-19.
- Modify build procedures for boost build v2.
- Add *-mt variants for libraries, or at least variants that use
  threads (regex and thread).

* Thu Nov 23 2006 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-10
- (#182414: boost: put tests in %%check section) via Rex Dieter
- Fix EVR with %%{?dist} tag via Gianluca Sforna

* Wed Nov 15 2006 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-9
- (#154784: boost-debuginfo package is empty)

* Tue Nov 14 2006 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-8
- (#205866: Revert scanner.hpp change.)

* Mon Nov 13 2006 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-7
- (#205866: boost::spirit generates warnings with -Wshadow)
- (#205863: serialization lib generates warnings)
- (#204326: boost RPM missing dependencies)
- (#193465: [SIGNAL/BIND] Regressions with GCC 4.1)
- BUILD_FLAGS, add, to see actual compile line.
- REGEX_FLAGS, add, to compile regex with ICU support.

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 1.33.1-6.1
- rebuild

* Tue May 16 2006 Karsten Hopp <karsten@redhat.de> 1.33.1-6
- buildrequire python-devel for Python.h

* Thu Feb 16 2006 Florian La Roche <laroche@redhat.com> - 1.33.1-5
- use the real version number to point to the shared libs

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 1.33.1-4.2
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 1.33.1-4.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Thu Jan 05 2006 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-4
- Fix symbolic links.

* Wed Jan 04 2006 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-3
- Update to boost-1.33.1.
- (#176485: Missing BuildRequires)
- (#169271: /usr/lib/libboost*.so.? links missing in package)

* Thu Dec 22 2005 Jesse Keating <jkeating@redhat.com> 1.33.1-2
- rebuilt

* Mon Nov 14 2005 Benjamin Kosnik <bkoz@redhat.com> 1.33.1-1
- Update to boost-1.33.1 beta.
- Run testsuite, gather results.

* Tue Oct 11 2005 Nils Philippsen <nphilipp@redhat.com> 1.33.0-4
- build require bzip2-devel and zlib-devel

* Tue Aug 23 2005 Benjamin Kosnik <bkoz@redhat.com> 1.33.0-3
- Create doc package again.
- Parts of the above by Neal Becker <ndbecker2@gmail.com>.

* Fri Aug 12 2005 Benjamin Kosnik <bkoz@redhat.com> 1.33.0-1
- Update to boost-1.33.0, update SONAME to 2 due to ABI changes.
- Simplified PYTHON_VERSION by Philipp Thomas <pth@suse.de>

* Tue May 24 2005 Benjamin Kosnik <bkoz@redhat.com> 1.32.0-6
- (#153093: boost warns that gcc 4.0.0 is an unknown compiler)
- (#152205: development .so symlinks should be in -devel subpackage)
- (#154783: linker .so symlinks missing from boost-devel package)

* Fri Mar 18 2005 Benjamin Kosnik <bkoz@redhat.com> 1.32.0-5
- Revert boost-base.patch to old behavior.
- Use SONAMEVERSION instead of dllversion.

* Wed Mar 16 2005 Benjamin Kosnik <bkoz@redhat.com> 1.32.0-4
- (#142612: Compiling Boost 1.32.0 Failed in RHEL 3.0 on Itanium2)
- (#150069: libboost_python.so is missing)
- (#141617: bad patch boost-base.patch)
- (#122817: libboost_*.so symlinks missing)
- Re-add boost-thread.patch.
- Change boost-base.patch to show thread tags.
- Change boost-gcc-tools.patch to use SOTAG, compile with dllversion.
- Add symbolic links to files.
- Sanity check can compile with gcc-3.3.x, gcc-3.4.2, gcc-4.0.x., gcc-4.1.x.

* Thu Dec 02 2004 Benjamin Kosnik <bkoz@redhat.com> 1.32.0-3
- (#122817: libboost_*.so symlinks missing)
- (#141574: half of the package is missing)
- (#141617: bad patch boost-base.patch)

* Wed Dec 01 2004 Benjamin Kosnik <bkoz@redhat.com> 1.32.0-2
- Remove bogus Obsoletes.

* Mon Nov 29 2004 Benjamin Kosnik <bkoz@redhat.com> 1.32.0-1
- Update to 1.32.0

* Wed Sep 22 2004 Than Ngo <than@redhat.com> 1.31.0-9
- cleanup specfile
- fix multiarch problem

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Wed May 05 2004 Warren Togami <wtogami@redhat.com> 1.31.0-7
- missing Obsoletes boost-python

* Mon May 03 2004 Benjamin Kosnik <bkoz@redhat.com>
- (#121630: gcc34 patch needed)

* Wed Apr 21 2004 Warren Togami <wtogami@redhat.com>
- #121415 FC2 BLOCKER: Obsoletes boost-python-devel, boost-doc
- other cleanups

* Tue Mar 30 2004 Benjamin Kosnik <bkoz@redhat.com>
- Remove bjam dependency. (via Graydon).
- Fix installed library names.
- Fix SONAMEs in shared libraries.
- Fix installed header location.
- Fix installed permissions.

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Mon Feb 09 2004 Benjamin Kosnik <bkoz@redhat.com> 1.31.0-2
- Update to boost-1.31.0

* Thu Jan 22 2004 Benjamin Kosnik <bkoz@redhat.com> 1.31.0-1
- Update to boost-1.31.0.rc2
- (#109307:  Compile Failure with boost libraries)
- (#104831:  Compile errors in apps using Boost.Python...)
- Unify into boost, boost-devel rpms.
- Simplify installation using bjam and prefix install.

* Tue Sep 09 2003 Nalin Dahyabhai <nalin@redhat.com> 1.30.2-2
- require boost-devel instead of devel in subpackages which require boost-devel
- remove stray Prefix: tag

* Mon Sep 08 2003 Benjamin Kosnik <bkoz@redhat.com> 1.30.2-1
- change license to Freely distributable
- verify installation of libboost_thread
- more boost-devel removals
- deal with lack of _REENTRANT on ia64/s390
- (#99458) rpm -e fixed via explict dir additions
- (#103293) update to 1.30.2

* Wed Jun 04 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Tue May 13 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- remove packager, change to new Group:

* Tue May 06 2003 Tim Powers <timp@redhat.com> 1.30.0-3
- add deffattr's so we don't have unknown users owning files
