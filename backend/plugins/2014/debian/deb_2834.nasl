# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2834-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.702834");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2013-7073", "CVE-2013-7074", "CVE-2013-7075", "CVE-2013-7076", "CVE-2013-7078", "CVE-2013-7079", "CVE-2013-7080", "CVE-2013-7081");
  script_name("Debian Security Advisory DSA 2834-1 (typo3-src - several vulnerabilities)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2014-01-01 00:00:00 +0100 (Wed, 01 Jan 2014)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2834.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"typo3-src on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), these problems have been fixed in
version 4.3.9+dfsg1-1+squeeze9.

For the stable distribution (wheezy), these problems have been fixed in
version 4.5.19+dfsg1-5+wheezy2.

For the testing distribution (jessie), these problems have been fixed in
version 4.5.32+dfsg1-1.

For the unstable distribution (sid), these problems have been fixed in
version 4.5.32+dfsg1-1.

We recommend that you upgrade your typo3-src packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in TYPO3, a content management
system. This update addresses cross-site scripting, information
disclosure, mass assignment, open redirection and insecure unserialize
vulnerabilities and corresponds to TYPO3-CORE-SA-2013-004
.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"typo3", ver:"4.3.9+dfsg1-1+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.3.9+dfsg1-1+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.3", ver:"4.3.9+dfsg1-1+squeeze9", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3", ver:"4.5.19+dfsg1-5+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.19+dfsg1-5+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.19+dfsg1-5+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.19+dfsg1-5+wheezy2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}