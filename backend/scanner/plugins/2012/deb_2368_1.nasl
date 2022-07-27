# OpenVAS Vulnerability Test
# $Id: deb_2368_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2368-1 (lighttpd)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70687");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-4362", "CVE-2011-3389");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 03:14:22 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2368-1 (lighttpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202368-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in lighttpd, a small and fast
webserver with minimal memory footprint.

CVE-2011-4362

Xi Wang discovered that the base64 decoding routine which is used to
decode user input during an HTTP authentication, suffers of a signedness
issue when processing user input.  As a result it is possible to force
lighttpd to perform an out-of-bounds read which results in Denial of
Service conditions.

CVE-2011-3389

When using CBC ciphers on an SSL enabled virtual host to communicate with
certain client, a so called BEAST attack allows man-in-the-middle
attackers to obtain plaintext HTTP traffic via a blockwise
chosen-boundary attack (BCBA) on an HTTPS session.  Technically this is
no lighttpd vulnerability.  However, lighttpd offers a workaround to
mitigate this problem by providing a possibility to disable CBC ciphers.

This updates includes this option by default. System administrators
are advised to read the NEWS file of this update (as this may break older
clients).


For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.19+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.28-2+squeeze1.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.30-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your lighttpd packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to lighttpd
announced via advisory DSA 2368-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.19-5+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.19-5+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.19-5+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.19-5+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.19-5+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.19-5+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.19-5+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd", ver:"1.4.28-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-doc", ver:"1.4.28-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-cml", ver:"1.4.28-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-magnet", ver:"1.4.28-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-mysql-vhost", ver:"1.4.28-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-trigger-b4-dl", ver:"1.4.28-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"lighttpd-mod-webdav", ver:"1.4.28-2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}