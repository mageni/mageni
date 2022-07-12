# OpenVAS Vulnerability Test
# $Id: deb_2893.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2893-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.702893");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2013-2053", "CVE-2013-6466");
  script_name("Debian Security Advisory DSA 2893-1 (openswan - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-03-31 00:00:00 +0200 (Mon, 31 Mar 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2893.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"openswan on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 2.6.28+dfsg-5+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in
version 2.6.37-3.1.

We recommend that you upgrade your openswan packages.");
  script_tag(name:"summary", value:"Two vulnerabilities were fixed in Openswan, an IKE/IPsec implementation
for Linux.

CVE-2013-2053
During an audit of Libreswan (with which Openswan shares some code),
Florian Weimer found a remote buffer overflow in the atodn()
function. This vulnerability can be triggered when Opportunistic
Encryption (OE) is enabled and an attacker controls the PTR record
of a peer IP address.
Authentication is not needed to trigger the vulnerability.

CVE-2013-6466
Iustina Melinte found a vulnerability in Libreswan which also
applies to the Openswan code. By carefully crafting IKEv2 packets, an
attacker can make the pluto daemon dereference non-received IKEv2
payload, leading to the daemon crash.
Authentication is not needed to trigger the vulnerability.

Patches were originally written to fix the vulnerabilities in Libreswan,
and have been ported to Openswan by Paul Wouters from the Libreswan
Project.

Since the Openswan package is not maintained anymore in the Debian
distribution and is not available in testing and unstable suites, it is
recommended for IKE/IPsec users to switch to a supported implementation
like strongSwan.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"openswan", ver:"2.6.28+dfsg-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan-dbg", ver:"2.6.28+dfsg-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan-doc", ver:"2.6.28+dfsg-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan-modules-dkms", ver:"2.6.28+dfsg-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan-modules-source", ver:"2.6.28+dfsg-5+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan", ver:"2.6.37-3.1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan-dbg", ver:"2.6.37-3.1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan-doc", ver:"2.6.37-3.1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan-modules-dkms", ver:"2.6.37-3.1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openswan-modules-source", ver:"2.6.37-3.1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}