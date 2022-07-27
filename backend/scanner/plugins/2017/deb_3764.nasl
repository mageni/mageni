# OpenVAS Vulnerability Test
# $Id: deb_3764.nasl 14280 2019-03-18 14:50:45Z cfischer $
# Auto-generated from advisory DSA 3764-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703764");
  script_version("$Revision: 14280 $");
  script_cve_id("CVE-2016-2120", "CVE-2016-7068", "CVE-2016-7072", "CVE-2016-7073",
                  "CVE-2016-7074");
  script_name("Debian Security Advisory DSA 3764-1 (pdns - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:50:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-13 00:00:00 +0100 (Fri, 13 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3764.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"pdns on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 3.4.1-4+deb8u7.

For the unstable distribution (sid), these problems have been fixed in
version 4.0.2-1.

We recommend that you upgrade your pdns packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been
discovered in pdns, an authoritative DNS server. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2016-2120
Mathieu Lafon discovered that pdns does not properly validate
records in zones. An authorized user can take advantage of this flaw
to crash server by inserting a specially crafted record in a zone
under their control and then sending a DNS query for that record.

CVE-2016-7068
Florian Heinz and Martin Kluge reported that pdns parses all records
present in a query regardless of whether they are needed or even
legitimate, allowing a remote, unauthenticated attacker to cause an
abnormal CPU usage load on the pdns server, resulting in a partial
denial of service if the system becomes overloaded.

CVE-2016-7072
Mongo discovered that the webserver in pdns is susceptible to a
denial-of-service vulnerability. A remote, unauthenticated attacker
to cause a denial of service by opening a large number of f TCP
connections to the web server.

CVE-2016-7073 /
CVE-2016-7074
Mongo discovered that pdns does not sufficiently validate TSIG
signatures, allowing an attacker in position of man-in-the-middle to
alter the content of an AXFR.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"pdns-backend-geo", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-ldap", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-lmdb", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-lua", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-mydns", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-mysql", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-pgsql", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-pipe", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-remote", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-sqlite3", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-server", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-server-dbg", ver:"3.4.1-4+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}