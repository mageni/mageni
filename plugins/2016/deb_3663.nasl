# OpenVAS Vulnerability Test
# $Id: deb_3663.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3663-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703663");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-7092", "CVE-2016-7094", "CVE-2016-7154");
  script_name("Debian Security Advisory DSA 3663-1 (xen - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-09 00:00:00 +0200 (Fri, 09 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3663.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"xen on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 4.4.1-9+deb8u7.

We recommend that you upgrade your xen packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2016-7092 (XSA-185)

Jeremie Boutoille of Quarkslab and Shangcong Luan of Alibaba
discovered a flaw in the handling of L3 pagetable entries, allowing
a malicious 32-bit PV guest administrator can escalate their
privilege to that of the host.

CVE-2016-7094 (XSA-187)

x86 HVM guests running with shadow paging use a subset of the x86
emulator to handle the guest writing to its own pagetables. Andrew
Cooper of Citrix discovered that there are situations a guest can
provoke which result in exceeding the space allocated for internal
state. A malicious HVM guest administrator can cause Xen to fail a
bug check, causing a denial of service to the host.

CVE-2016-7154 (XSA-188)

Mikhail Gorobets of Advanced Threat Research, Intel Security
discovered a use after free flaw in the FIFO event channel code. A
malicious guest administrator can crash the host, leading to a
denial of service. Arbitrary code execution (and therefore privilege
escalation), and information leaks, cannot be excluded.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libxen-4.4:amd64", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-4.4:i386", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxenstore3.0:amd64", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxenstore3.0:i386", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.4-amd64", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.4-arm64", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.4-armhf", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-4.4", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.4.1-9+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}