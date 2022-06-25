# OpenVAS Vulnerability Test
# $Id: deb_2648.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2648-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892648");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-2492", "CVE-2012-5529");
  script_name("Debian Security Advisory DSA 2648-1 (firebird2.5 - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-15 00:00:00 +0100 (Fri, 15 Mar 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2648.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_tag(name:"affected", value:"firebird2.5 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), these problems have been fixed in
version 2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your firebird2.5 packages.");
  script_tag(name:"summary", value:"A buffer overflow was discovered in the Firebird database server, which
could result in the execution of arbitrary code. In addition, a denial
of service vulnerability was discovered in the TraceManager.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"firebird2.5-classic", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-classic-common", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-common", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-common-doc", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-dev", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-doc", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-examples", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-server-common", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-super", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"firebird2.5-superclassic", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfbclient2", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfbembed2.5", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libib-util", ver:"2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}