# OpenVAS Vulnerability Test
# $Id: deb_2388_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2388-1 (t1lib)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70707");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 03:27:53 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2388-1 (t1lib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202388-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in t1lib, a Postscript Type 1
font rasterizer library, some of which might lead to code execution
through the opening of files embedding bad fonts.

CVE-2010-2642
A heap-based buffer overflow in the AFM font metrics parser
potentially leads to the execution of arbitrary code.

CVE-2011-0433
Another heap-based buffer overflow in the AFM font metrics
parser potentially leads to the execution of arbitrary code.

CVE-2011-0764
An invalid pointer dereference allows execution of arbitrary
code using crafted Type 1 fonts.

CVE-2011-1552
Another invalid pointer dereference results in an application
crash, triggered by crafted Type 1 fonts.

CVE-2011-1553
A use-after-free vulnerability results in an application
crash, triggered by crafted Type 1 fonts.

CVE-2011-1554
An off-by-one error results in an invalid memory read and
application crash, triggered by crafted Type 1 fonts.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.1.2-3+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 5.1.2-3+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 5.1.2-3.3.

For the unstable distribution (sid), this problem has been fixed in
version 5.1.2-3.3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your t1lib packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to t1lib
announced via advisory DSA 2388-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libt1-5", ver:"5.1.2-3+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-5-dbg", ver:"5.1.2-3+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-dev", ver:"5.1.2-3+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-doc", ver:"5.1.2-3+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"t1lib-bin", ver:"5.1.2-3+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-5", ver:"5.1.2-3+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-5-dbg", ver:"5.1.2-3+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-dev", ver:"5.1.2-3+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-doc", ver:"5.1.2-3+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"t1lib-bin", ver:"5.1.2-3+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-5", ver:"5.1.2-3.5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-5-dbg", ver:"5.1.2-3.5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-dev", ver:"5.1.2-3.5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libt1-doc", ver:"5.1.2-3.5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"t1lib-bin", ver:"5.1.2-3.5", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}