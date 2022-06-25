# OpenVAS Vulnerability Test
# $Id: deb_2363_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2363-1 (tor)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70575");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-2778");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 02:34:19 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2363-1 (tor)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202363-1");
  script_tag(name:"insight", value:"It was discovered that Tor, an online privacy tool, incorrectly computes
buffer sizes in certain cases involving SOCKS connections.  Malicious
parties could use this to cause a heap-based buffer overflow, potentially
allowing execution of arbitrary code.

In Tor's default configuration this issue can only be triggered by
clients that can connect to Tor's socks port, which listens only on
localhost by default.

In non-default configurations where Tor's SocksPort listens not only on
localhost or where Tor was configured to use another socks server for all of
its outgoing connections, Tor is vulnerable to a larger set of malicious
parties.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.2.1.32-1.

For the stable distribution (squeeze), this problem has been fixed in
version 0.2.2.35-1~squeeze+1.

For the unstable and testing distributions, this problem has been fixed in
version 0.2.2.35-1.

For the experimental distribution, this problem has has fixed in
version 0.2.3.10-alpha-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your tor packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to tor
announced via advisory DSA 2363-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tor", ver:"0.2.1.32-1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.1.32-1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.1.32-1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor", ver:"0.2.2.35-1~squeeze+1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.2.35-1~squeeze+1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.2.35-1~squeeze+1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}