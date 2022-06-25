# OpenVAS Vulnerability Test
# $Id: deb_3535.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3535-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703535");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-2385");
  script_name("Debian Security Advisory DSA 3535-1 (kamailio - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-29 00:00:00 +0200 (Tue, 29 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3535.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"kamailio on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
this problem has been fixed in version 4.2.0-2+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 4.3.4-2.

For the unstable distribution (sid), this problem has been fixed in
version 4.3.4-2.

We recommend that you upgrade your kamailio packages.");
  script_tag(name:"summary", value:"Stelios Tsampas discovered a buffer
overflow in the Kamailio SIP proxy which might result in the execution of
arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kamailio", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-autheph-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-autheph-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-berkeley-bin", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-berkeley-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-berkeley-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-carrierroute-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-carrierroute-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-cpl-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-cpl-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-dbg:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-dbg:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-dnssec-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-dnssec-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-extra-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-extra-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-geoip-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-geoip-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-ims-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-ims-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-java-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-java-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-json-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-json-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-ldap-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-ldap-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-lua-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-lua-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-memcached-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-memcached-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-mono-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-mono-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-mysql-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-mysql-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-outbound-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-outbound-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-perl-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-perl-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-postgres-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-postgres-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-presence-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-presence-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-python-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-python-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-radius-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-radius-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-redis-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-redis-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-sctp-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-sctp-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-snmpstats-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-snmpstats-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-sqlite-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-sqlite-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-tls-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-tls-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-unixodbc-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-unixodbc-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-utils-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-utils-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-websocket-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-websocket-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-xml-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-xml-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-xmpp-modules:amd64", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-xmpp-modules:i386", ver:"4.2.0-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-autheph-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-autheph-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-berkeley-bin", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-berkeley-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-berkeley-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-carrierroute-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-carrierroute-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-cnxcc-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-cnxcc-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-cpl-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-cpl-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-dbg:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-dbg:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-dnssec-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-dnssec-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-erlang-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-erlang-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-extra-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-extra-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-geoip-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-geoip-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-ims-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-ims-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-java-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-java-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-json-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-json-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-kazoo-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-kazoo-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-ldap-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-ldap-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-lua-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-lua-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-memcached-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-memcached-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-mono-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-mono-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-mysql-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-mysql-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-outbound-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-outbound-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-perl-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-perl-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-postgres-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-postgres-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-presence-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-presence-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-purple-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-purple-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-python-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-python-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-radius-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-radius-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-redis-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-redis-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-sctp-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-sctp-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-snmpstats-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-snmpstats-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-sqlite-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-sqlite-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-tls-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-tls-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-unixodbc-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-unixodbc-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-utils-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-utils-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-websocket-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-websocket-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-xml-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-xml-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"kamailio-xmpp-modules:amd64", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kamailio-xmpp-modules:i386", ver:"4.3.4-2", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}