# OpenVAS Vulnerability Test
# $Id: deb_2636.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2636-2 using nvtgen 1.0
# Script version: 2.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.892636");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2012-5511", "CVE-2012-5634", "CVE-2012-4544", "CVE-2013-0153");
  script_name("Debian Security Advisory DSA 2636-2 (xen - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-03 00:00:00 +0100 (Sun, 03 Mar 2013)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2636.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"xen on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), these problems have been fixed in
version 4.0.1-5.8.

For the testing distribution (wheezy), these problems have been fixed in
version 4.1.4-2.

For the unstable distribution (sid), these problems have been fixed in
version 4.1.4-2.

We recommend that you upgrade your xen packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor.
The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2012-4544
Insufficient validation of kernel or ramdisk sizes in the Xen PV
domain builder could result in denial of service.

CVE-2012-5511
Several HVM control operations performed insufficient validation of
input, which could result in denial of service through resource
exhaustion.

CVE-2012-5634
Incorrect interrupt handling when using VT-d hardware could result
in denial of service.

CVE-2013-0153
Insufficient restriction of interrupt access could result in denial
of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.0.1-5.8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.0.1-5.8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-docs-4.0", ver:"4.0.1-5.8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.0-amd64", ver:"4.0.1-5.8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.0-i386", ver:"4.0.1-5.8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-4.0", ver:"4.0.1-5.8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.0.1-5.8", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-4.1", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-ocaml", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-ocaml-dev", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-docs-4.1", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.1-amd64", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.1-i386", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-i386", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-4.1", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.1.4-2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}