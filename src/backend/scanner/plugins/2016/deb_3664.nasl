# OpenVAS Vulnerability Test
# $Id: deb_3664.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3664-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703664");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-5426", "CVE-2016-5427", "CVE-2016-6172");
  script_name("Debian Security Advisory DSA 3664-1 (pdns - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-10 00:00:00 +0200 (Sat, 10 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3664.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"pdns on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 3.4.1-4+deb8u6.

We recommend that you upgrade your pdns packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in pdns, an authoritative
DNS server. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2016-5426 / CVE-2016-5427
Florian Heinz and Martin Kluge reported that the PowerDNS
Authoritative Server accepts queries with a qname's length larger
than 255 bytes and does not properly handle dot inside labels. A
remote, unauthenticated attacker can take advantage of these flaws
to cause abnormal load on the PowerDNS backend by sending specially
crafted DNS queries, potentially leading to a denial of service.

CVE-2016-6172
It was reported that a malicious primary DNS server can crash a
secondary PowerDNS server due to improper restriction of zone size
limits. This update adds a feature to limit AXFR sizes in response
to this flaw.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"pdns-backend-geo", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-ldap", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-lmdb", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-lua", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-mydns", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-mysql", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-pgsql", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-pipe", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-remote", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-sqlite3", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-server", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-server-dbg", ver:"3.4.1-4+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}