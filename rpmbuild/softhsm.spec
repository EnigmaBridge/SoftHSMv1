Summary: Software version of a PKCS#11 Hardware Security Module Proxy for EnigmaBridge
Name: softhsm-eb
Version: 1.3.8
Release: 1%{?dist}
License: BSD
Url: http://www.opendnssec.org/
Source: http://www.opendnssec.org/files/source/%{name}-%{version}.tar.gz
Group: Applications/System
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: botan-devel >= 1.8.5 sqlite-devel >= 3.4.2
Requires(pre): shadow-utils

%description
EnigmaBridge SoftHSM connector.
OpenDNSSEC is providing a software implementation of a generic 
cryptographic device with a PKCS#11 interface, the SoftHSM. SoftHSM is 
designed to meet the requirements of OpenDNSSEC, but can also work together 
with other cryptographic products because of the PKCS#11 interface.

%package devel
Summary: Development package of softhsm that includes the header files
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}, botan-devel, sqlite-devel

%description devel
The devel package contains the libsofthsm include files

%prep
%setup -q 

%build
%configure --libdir=%{_libdir}/ 
make %{?_smp_mflags}

%check
make check

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install
rm %{buildroot}/etc/softhsm.conf.sample
rm -f %{buildroot}/%{_libdir}/softhsm/*a
mkdir -p %{buildroot}%{_includedir}/softhsm
cp src/lib/*.h %{buildroot}%{_includedir}/softhsm
mkdir -p %{buildroot}/var/softhsm

%files 
%config(noreplace) %{_sysconfdir}/softhsm.conf
%{_bindir}/*
%dir %{_libdir}/softhsm/
%{_libdir}/softhsm/libsofthsm.so
%attr(0770,ods,ods) %dir /var/softhsm
%doc AUTHORS NEWS README
%{_mandir}/*/*

%files devel
%defattr(-,root,root,-)
%attr(0755,root,root) %dir %{_includedir}/softhsm
%{_includedir}/softhsm/*.h
%doc README

%pre
getent group ods >/dev/null || groupadd -r ods ||:
getent passwd ods >/dev/null || \
    useradd -r -g ods -d /var/softhsm -s /sbin/nologin \
    -c "DNSSEC private keys owner" ods ||:

%changelog
* Mon Apr 13 2015 Paul Wouters <pwouters@redhat.com> - 1.3.5-2
- Minor fixes in post and minor cleanup, bump for forgotten build

* Sun Nov 03 2013 Paul Wouters <pwouters@redhat.com> - 1.3.5-1
- Updated to 1.3.5

* Mon Jun 04 2012 Paul Wouters <pwouters@redhat.com> - 1.3.3-1
- Updated to 1.3.3

* Tue Apr 03 2012 Paul Wouters <pwouters@redhat.com> - 1.3.2-1
- Updated to 1.3.2.
- Changed user from opendnssec to ods, as used in the opendnssec package

* Thu Oct 27 2011 Paul Wouters <paul@xelerance.com> - 1.3.0-3
- Initial Fedora package
- Do not install the .a file
- Use a separate "opendnssec" user to own /var/sofhsm

* Tue Oct 25 2011 Paul Wouters <paul@xelerance.com> - 1.3.0-2
- Fix description texts w.r.t. include files

* Wed Oct 05 2011 Paul Wouters <paul@xelerance.com> - 1.3.0-1
- Upgraded to 1.3.0

* Thu Mar  3 2011 Paul Wouters <paul@xelerance.com> - 1.2.0-1
- Initial package for Fedora 
