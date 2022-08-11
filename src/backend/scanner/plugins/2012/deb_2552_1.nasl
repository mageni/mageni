# OpenVAS Vulnerability Test
# $Id: deb_2552_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2552-1 (tiff)
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
  script_oid("1.3.6.1.4.1.25623.1.0.72443");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2482", "CVE-2010-2595", "CVE-2010-2597", "CVE-2010-2630", "CVE-2010-4665", "CVE-2012-2113", "CVE-2012-3401");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-10-03 11:10:30 -0400 (Wed, 03 Oct 2012)");
  script_name("Debian Security Advisory DSA 2552-1 (tiff)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202552-1");
  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Tiff, a library set and tools
to support the Tag Image File Format (TIFF), allowing denial of service and
potential privilege escalation.

These vulnerabilities can be exploited via a specially crafted TIFF image.

CVE-2012-2113
The tiff2pdf utility has an integer overflow error when parsing images.

CVE-2012-3401
Huzaifa Sidhpurwala discovered heap-based buffer overflow in the
t2p_read_tiff_init() function.

CVE-2010-2482
An invalid td_stripbytecount field is not properly handle and can trigger a
NULL pointer dereference.

CVE-2010-2595
An array index error, related to downsampled OJPEG input. in the
TIFFYCbCrtoRGB function causes an unexpected crash.

CVE-2010-2597
Also related to downsampled OJPEG input, the TIFFVStripSize function crash
unexpectly.

CVE-2010-2630
The TIFFReadDirectory function does not properly validate the data types of
codec-specific tags that have an out-of-order position in a TIFF file.

CVE-2010-4665
The tiffdump utility has an integer overflow in the ReadDirectory function.

For the stable distribution (squeeze), these problems have been fixed in
version 3.9.4-5+squeeze5.

For the testing distribution (wheezy), these problems have been fixed in
version 4.0.2-2.

For the unstable distribution (sid), these problems have been fixed in
version 4.0.2-2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your tiff packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to tiff
announced via advisory DSA 2552-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.9.4-5+squeeze5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.9.4-5+squeeze5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.9.4-5+squeeze5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.4-5+squeeze5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.9.4-5+squeeze5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.9.4-5+squeeze5", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.2-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.2-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.2-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5-alt-dev", ver:"4.0.2-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.2-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.2-2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}