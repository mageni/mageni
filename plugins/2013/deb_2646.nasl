# OpenVAS Vulnerability Test
# $Id: deb_2646.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2646-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.892646");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-1842", "CVE-2013-1843");
  script_name("Debian Security Advisory DSA 2646-1 (typo3-src - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-15 00:00:00 +0100 (Fri, 15 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2646.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"typo3-src on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), these problems have been fixed in
version 4.3.9+dfsg1-1+squeeze8.

For the testing distribution (wheezy), these problems have been fixed in
version 4.5.19+dfsg1-5.

For the unstable distribution (sid), these problems have been fixed in
version 4.5.19+dfsg1-5.

We recommend that you upgrade your typo3-src packages.");
  script_tag(name:"summary", value:"TYPO3, a PHP-based content management system, was found vulnerable to several vulnerabilities.

CVE-2013-1842
Helmut Hummel and Markus Opahle discovered that the Extbase database layer
was not correctly sanitizing user input when using the Query object model.
This can lead to SQL injection by a malicious user inputing crafted
relation values.

CVE-2013-1843
Missing user input validation in the access tracking mechanism could lead
to arbitrary URL redirection.

Note: the fix will break already published links. Upstream advisory
TYPO3-CORE-SA-2013-001

has more information on how to mitigate that.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"typo3", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.3", ver:"4.3.9+dfsg1-1+squeeze8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}