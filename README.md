# keymaster
Short term certificate based identity system.

Keymaster is a system which issues short-lived credentials (SSH certs,
SSL certs, Kerberos tickets, API keys, etc.) to users and automation
accounts. This system is easy to use, configure and administer.

Please see the
[design document](https://docs.google.com/document/d/1AW3UROCJqTc3R4MLJXxmPUNS0OFNcsiQJ_Q4j--5tQE/pub) for more information.


## Getting Started

### Prerequisites
* go >= 1.8 
* make

### Building
1. make get-deps
2. make

This will leave you with three binaries: prodme, keymaster, and unlocker

### Running

#### keymaster (server)

##### Configuring 
You will need to create a new valid server config. Keymaster facilitates this
with the option `-generateConfig`. After running the keymaster binary with
this option you will be left with a valid config with an encrypted master secret 
and self signed certificates SSL certificates. This config file will also
be using an apache password file for user authentication.

###### User password backends
For password backend keymaster currently supports LDAP backends and apache
password files. For LDAP the `bind_pattern` is a printf string where `%s` is
the place where the username will be substituted. For example for an 389ds/openldap
string might be: `"uid=%s,ou=People,dc=example,dc=com`. 

###### User token backend
For u2f/profile backend keymaster supports SQLite and PostgreSQL. The
`storage_url` field contains the connection information for the database.
If no `storage_url` is defined keymaster will use an SQLite database located
in the configured data directory for keymaster.

En example of a postgresql url is:
`postgresql://dbusername:dbpassword.example.com/keymasterdbname`

#### prodme (client)



## Contributions

Prior to receiving information from any contributor, Symantec requires
that all contributors complete, sign, and submit Symantec Personal
Contributor Agreement (SPCA).

Please read [contributions](CONTRIBUTING.md) for details.


## LICENSE

Copyright 2016 Symantec Corporation.

Licensed under the Apache License, Version 2.0 (the “License”); you
may not use this file except in compliance with the License.

You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0 Unless required by
applicable law or agreed to in writing, software distributed under the
License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for
the specific language governing permissions and limitations under the
License.
