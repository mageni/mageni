# OpenVAS Vulnerability Test
# $Id: deb_3629.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3629-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703629");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-7974", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979",
                  "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548",
                  "CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518");
  script_name("Debian Security Advisory DSA 3629-1 (ntp - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-02 10:56:41 +0530 (Tue, 02 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3629.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"ntp on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 1:4.2.6.p5+dfsg-7+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 1:4.2.8p7+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 1:4.2.8p7+dfsg-1.

We recommend that you upgrade your ntp packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in the Network Time Protocol daemon and utility programs:

CVE-2015-7974
Matt Street discovered that insufficient key validation allows
impersonation attacks between authenticated peers.

CVE-2015-7977CVE-2015-7978Stephen Gray discovered that a NULL pointer dereference
and a buffer overflow in the handling of ntpdc reslist
commands may
result in denial of service.

CVE-2015-7979
Aanchal Malhotra discovered that if NTP is configured for broadcast
mode, an attacker can send malformed authentication packets which
break associations with the server for other broadcast clients.

CVE-2015-8138
Matthew van Gundy and Jonathan Gardner discovered that missing
validation of origin timestamps in ntpd clients may result in denial
of service.

CVE-2015-8158
Jonathan Gardner discovered that missing input sanitising in ntpq
may result in denial of service.

CVE-2016-1547
Stephen Gray and Matthew van Gundy discovered that incorrect handling
of crypto NAK packets may result in denial of service.

CVE-2016-1548
Jonathan Gardner and Miroslav Lichvar discovered that ntpd clients
could be forced to change from basic client/server mode to interleaved
symmetric mode, preventing time synchronisation.

CVE-2016-1550
Matthew van Gundy, Stephen Gray and Loganaden Velvindron discovered
that timing leaks in the the packet authentication code could result
in recovery of a message digest.

CVE-2016-2516Yihan Lian discovered that duplicate IPs on unconfig
directives will
trigger an assert.

CVE-2016-2518
Yihan Lian discovered that an OOB memory access could potentially
crash ntpd.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p7+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.8p7+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.8p7+dfsg-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-7+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-7+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-7+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}