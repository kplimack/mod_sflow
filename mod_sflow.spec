Summary: Apache module to implement logging using sFlow
Name: mod-sflow
Version: 1.0.3
Release: 1%{?dist}
License: http://www.inmon.com/technology/sflowlicense.txt
Group: System Environment/Daemons
URL: http://code.google.com/p/mod-sflow/
Source: http://mod-sflow.googlecode.com/files/mod-sflow-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: hsflowd httpd httpd-mmn = %([ -a %{_includedir}/httpd/.mmn ] && cat %{_includedir}/httpd/.mmn || echo missing)
BuildRequires: httpd-devel

%description
Apache module to implement logging using sFlow (http://www.sflow.org).
The purpose is for continuous, real-time monitoring of large web clusters.
The sFlow mechanism allows for a random 1-in-N sample of the URL transactions
to be reported, along with a periodic snapshot of the most important counters,
all using sFlow's efficient XDR-encoded UDP "push" model. There is no limit
to the number of web-servers that can be sending to a single sFlow collector.

%prep

%setup -q -n %{name}-%{version}

%build
/usr/sbin/apxs -Wc,"%{optflags}" -c mod_sflow.c sflow_api.c

%install
mkdir -p %{buildroot}%{_sysconfdir}/httpd/conf.d/
install -Dp .libs/mod_sflow.so %{buildroot}%{_libdir}/httpd/modules/mod_sflow.so

cat << EOF > %{buildroot}%{_sysconfdir}/httpd/conf.d/mod_sflow.conf
LoadModule sflow_module modules/mod_sflow.so

<IfModule mod_sflow.c>
  <Location /sflow>
    SetHandler sflow
  </Location>
</IfModule>
EOF

%clean
rm -rf %{buildroot}

%files
%defattr (-,root,root)
%doc README
%{_libdir}/httpd/modules/mod_sflow.so
%config(noreplace) %{_sysconfdir}/httpd/conf.d/mod_sflow.conf

%changelog
* Fri Feb 3 2012 Ian Meyer <ianmmeyer@gmail.com> 0.9.14
Initial spec to build mod_sflow RPM
