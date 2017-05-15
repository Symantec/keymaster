Name:           keymaster
Version:        0.1.0
Release:        1%{?dist}
Summary:        Short term access certificate generator and client

#Group:
License:        ASL 2.0
URL:            https://github.com/cviecco/simple-cloud-encrypt/
Source0:        keymaster-%{version}.tar.gz

#BuildRequires: golang
#Requires:

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

%files
#%doc
%{_sbindir}/keymaster
%{_bindir}/getcreds


%changelog


