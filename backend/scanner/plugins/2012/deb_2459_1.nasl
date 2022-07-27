# OpenVAS Vulnerability Test
# $Id: deb_2459_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2459-1 (quagga)
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
  script_oid("1.3.6.1.4.1.25623.1.0.71263");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-04-30 07:58:15 -0400 (Mon, 30 Apr 2012)");
  script_name("Debian Security Advisory DSA 2459-1 (quagga)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202459-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Quagga, a routing
daemon.

CVE-2012-0249
A buffer overflow in the ospf_ls_upd_list_lsa function in the
OSPFv2 implementation allows remote attackers to cause a
denial of service (assertion failure and daemon exit) via a
Link State Update (aka LS Update) packet that is smaller than
the length specified in its header.

CVE-2012-0250
A buffer overflow in the OSPFv2 implementation allows remote
attackers to cause a denial of service (daemon crash) via a
Link State Update (aka LS Update) packet containing a
network-LSA link-state advertisement for which the
data-structure length is smaller than the value in the Length
header field.

CVE-2012-0255
The BGP implementation does not properly use message buffers
for OPEN messages, which allows remote attackers impersonating
a configured BGP peer to cause a denial of service (assertion
failure and daemon exit) via a message associated with a
malformed AS4 capability.

This security update upgrades the quagga package to the most recent
upstream release.  This release includes other corrections, such as
hardening against unknown BGP path attributes.

For the stable distribution (squeeze), these problems have been fixed
in version 0.99.20.1-0+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 0.99.20.1-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your quagga packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to quagga
announced via advisory DSA 2459-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"quagga", ver:"0.99.20.1-0+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.20.1-0+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga", ver:"0.99.20.1-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-dbg", ver:"0.99.20.1-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.20.1-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}