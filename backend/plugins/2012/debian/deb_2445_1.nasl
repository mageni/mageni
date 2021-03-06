# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2445-1 (typo3-src)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.71247");
  script_cve_id("CVE-2012-1606", "CVE-2012-1607", "CVE-2012-1608");
  script_version("2021-11-23T15:20:34+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2012-04-30 07:55:30 -0400 (Mon, 30 Apr 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Debian Security Advisory DSA 2445-1 (typo3-src)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202445-1");
  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework:

CVE-2012-1606
Failing to properly HTML-encode user input in several places,
the TYPO3 backend is susceptible to Cross-Site Scripting. A
valid backend user is required to exploit these
vulnerabilities.

CVE-2012-1607
Accessing a CLI Script directly with a browser may disclose
the database name used for the TYPO3 installation.

CVE-2012-1608
By not removing non printable characters, the API method
t3lib_div::RemoveXSS() fails to filter specially crafted HTML
injections, thus is susceptible to Cross-Site Scripting.

For the stable distribution (squeeze), these problems have been fixed in
version 4.3.9+dfsg1-1+squeeze3.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 4.5.14+dfsg1-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your typo3-src packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to typo3-src
announced via advisory DSA 2445-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"typo3", ver:"4.3.9+dfsg1-1+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.3.9+dfsg1-1+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.3", ver:"4.3.9+dfsg1-1+squeeze4", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3", ver:"4.5.15+dfsg1-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.15+dfsg1-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.15+dfsg1-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.15+dfsg1-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}