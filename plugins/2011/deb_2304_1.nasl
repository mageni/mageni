# OpenVAS Vulnerability Test
# $Id: deb_2304_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2304-1 (squid3)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.70241");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3205");
  script_name("Debian Security Advisory DSA 2304-1 (squid3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202304-1");
  script_tag(name:"insight", value:"Ben Hawkes discovered that squid3, a full featured Web Proxy cache
(HTTP proxy), is vulnerable to a buffer overflow when processing gopher
server replies.  An attacker can exploit this flaw by connecting to a
gopher server that returns lines longer than 4096 bytes.  This may result
in denial of service conditions (daemon crash) or the possibly the
execution of arbitrary code with rights of the squid daemon.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.0.STABLE8-3+lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 3.1.6-1.2+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 3.1.15-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.1.15-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your squid3 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to squid3
announced via advisory DSA 2304-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"squid3", ver:"3.0.STABLE8-3+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-cgi", ver:"3.0.STABLE8-3+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-common", ver:"3.0.STABLE8-3+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squidclient", ver:"3.0.STABLE8-3+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid-cgi", ver:"3.1.6-1.2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3", ver:"3.1.6-1.2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-common", ver:"3.1.6-1.2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-dbg", ver:"3.1.6-1.2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squidclient", ver:"3.1.6-1.2+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid-cgi", ver:"3.1.15-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3", ver:"3.1.15-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-common", ver:"3.1.15-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squid3-dbg", ver:"3.1.15-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"squidclient", ver:"3.1.15-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}