###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1599.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1599-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891599");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857",
                "CVE-2016-2858", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037",
                "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4952",
                "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5238", "CVE-2016-5337",
                "CVE-2016-5338", "CVE-2016-6351", "CVE-2016-6834", "CVE-2016-6836", "CVE-2016-6888",
                "CVE-2016-7116", "CVE-2016-7155", "CVE-2016-7156", "CVE-2016-7161", "CVE-2016-7170",
                "CVE-2016-7421", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8577", "CVE-2016-8578",
                "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103",
                "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106", "CVE-2017-10664", "CVE-2018-10839",
                "CVE-2018-17962", "CVE-2018-17963");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1599-1] qemu security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-03 00:00:00 +0100 (Mon, 03 Dec 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00038.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"qemu on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:2.1+dfsg-12+deb8u8.

We recommend that you upgrade your qemu packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were found in QEMU, a fast processor emulator:

CVE-2016-2391

Zuozhi Fzz discovered that eof_times in USB OHCI emulation support
could be used to cause a denial of service, via a null pointer
dereference.

CVE-2016-2392 / CVE-2016-2538

Qinghao Tang found a NULL pointer dereference and multiple integer
overflows in the USB Net device support that could allow local guest
OS administrators to cause a denial of service. These issues related
to remote NDIS control message handling.

CVE-2016-2841

Yang Hongke reported an infinite loop vulnerability in the NE2000 NIC
emulation support.

CVE-2016-2857

Liu Ling found a flaw in QEMU IP checksum routines. Attackers could
take advantage of this issue to cause QEMU to crash.

CVE-2016-2858

Arbitrary stack based allocation in the Pseudo Random Number Generator
(PRNG) back-end support.

Description truncated. Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}