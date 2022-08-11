###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4115.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4115-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704115");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_name("Debian Security Advisory DSA 4115-1 (quagga - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-15 00:00:00 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4115.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"quagga on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 0.99.23.1-1+deb8u5.

For the stable distribution (stretch), these problems have been fixed in
version 1.1.1-3+deb9u2.

We recommend that you upgrade your quagga packages.

For the detailed security status of quagga  please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/quagga");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in Quagga, a routing
daemon. The Common Vulnerabilities and Exposures project identifies the
following issues:

CVE-2018-5378
It was discovered that the Quagga BGP daemon, bgpd, does not
properly bounds check data sent with a NOTIFY to a peer, if an
attribute length is invalid. A configured BGP peer can take
advantage of this bug to read memory from the bgpd process or cause
a denial of service (daemon crash).

CVE-2018-5379
It was discovered that the Quagga BGP daemon, bgpd, can double-free
memory when processing certain forms of UPDATE message, containing
cluster-list and/or unknown attributes, resulting in a denial of
service (bgpd daemon crash).

CVE-2018-5380
It was discovered that the Quagga BGP daemon, bgpd, does not
properly handle internal BGP code-to-string conversion tables.


CVE-2018-5381
It was discovered that the Quagga BGP daemon, bgpd, can enter an
infinite loop if sent an invalid OPEN message by a configured peer.
A configured peer can take advantage of this flaw to cause a denial
of service (bgpd daemon not responding to any other events, BGP
sessions will drop and not be reestablished, unresponsive CLI
interface).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"quagga", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-bgpd", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-core", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-doc", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-isisd", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-ospf6d", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-ospfd", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-pimd", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-ripd", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-ripngd", ver:"1.1.1-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga", ver:"0.99.23.1-1+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-dbg", ver:"0.99.23.1-1+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.23.1-1+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}