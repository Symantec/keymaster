Name:           keymaster
Version:        0.2.0
Release:        1%{?dist}
Summary:        Short term access certificate generator and client

#Group:
License:        ASL 2.0
URL:            https://github.com/cviecco/simple-cloud-encrypt/
Source0:        keymaster-%{version}.tar.gz

#BuildRequires: golang
#Requires:
Requires(pre): /usr/sbin/useradd, /usr/bin/getent
Requires(postun): /usr/sbin/userdel

#no debug package as this is go
%define debug_package %{nil}

%description
Simple utilites for checking state of ldap infrastructure


%prep
%setup -n %{name}-%{version}


%build
make


%install
#%make_install
%{__install} -Dp -m0755 bin/keymaster %{buildroot}%{_sbindir}/keymaster
%{__install} -Dp -m0755 bin/getcreds %{buildroot}%{_bindir}/getcreds
install -d %{buildroot}/usr/lib/systemd/system
install -p -m 0644 misc/startup/keymaster.service %{buildroot}/usr/lib/systemd/system/keymaster.service

%pre
/usr/bin/getent passwd keymaster || useradd -d /var/lib/keymaster -s /bin/false -U -r  keymaster

%post
mkdir -p /etc/keymaster/
systemctl daemon-reload

%postun
/usr/sbin/userdel keymaster
systemctl daemon-reload

%files
#%doc
%{_sbindir}/keymaster
%{_bindir}/getcreds
/usr/lib/systemd/system/keymaster.service


%changelog


