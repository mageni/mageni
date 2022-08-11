# OpenVAS Vulnerability Test
# $Id: deb_2316_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2316-1 (quagga)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70405");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327");
  script_name("Debian Security Advisory DSA 2316-1 (quagga)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202316-1");
  script_tag(name:"insight", value:"Riku Hietamaki, Tuomo Untinen and Jukka Taimisto discovered several
vulnerabilities in Quagga, an Internet routing daemon:

CVE-2011-3323
A stack-based buffer overflow while decoding Link State Update
packets with a malformed Inter Area Prefix LSA can cause the
ospf6d process to crash or (potentially) execute arbitrary
code.

CVE-2011-3324
The ospf6d process can crash while processing a Database
Description packet with a crafted Link-State-Advertisement.

CVE-2011-3325
The ospfd process can crash while processing a crafted Hello
packet.

CVE-2011-3326
The ospfd process crashes while processing
Link-State-Advertisements of a type not known to Quagga.

CVE-2011-3327
A heap-based buffer overflow while processing BGP UPDATE
messages containing an Extended Communities path attribute
can cause the bgpd process to crash or (potentially) execute
arbitrary code.

The OSPF-related vulnerabilities require that potential attackers send
packets to a vulnerable Quagga router. The packets are not distributed
over OSPF. In contrast, the BGP UPDATE messages could be propagated
by some routers.

For the oldstable distribution (lenny), these problems have been fixed
in version 0.99.10-1lenny6.

For the stable distribution (squeeze), these problems have been fixed
in version 0.99.17-2+squeeze3.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 0.99.19-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your quagga packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to quagga
announced via advisory DSA 2316-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"quagga", ver:"0.99.10-1lenny6", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.10-1lenny6", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga", ver:"0.99.17-2+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.17-2+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga", ver:"0.99.20-1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.20-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}