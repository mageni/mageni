###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1497.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1497-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891497");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2015-8666", "CVE-2016-10155", "CVE-2016-2198", "CVE-2016-6833", "CVE-2016-6835",
                "CVE-2016-8576", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-9602", "CVE-2016-9603",
                "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9914", "CVE-2016-9915",
                "CVE-2016-9916", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-10806", "CVE-2017-10911",
                "CVE-2017-11434", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15289", "CVE-2017-16845",
                "CVE-2017-18030", "CVE-2017-18043", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5525",
                "CVE-2017-5526", "CVE-2017-5579", "CVE-2017-5667", "CVE-2017-5715", "CVE-2017-5856",
                "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505", "CVE-2017-7377", "CVE-2017-7493",
                "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8112", "CVE-2017-8309",
                "CVE-2017-8379", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9503",
                "CVE-2018-5683", "CVE-2018-7550");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1497-1] qemu security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-07 00:00:00 +0200 (Fri, 07 Sep 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00007.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"qemu on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:2.1+dfsg-12+deb8u7.

We recommend that you upgrade your qemu packages.");
  script_tag(name:"summary", value:"Infinite loop issues in the USB xHCI, in the transfer mode register
of the SDHCI protocol, and the USB ohci_service_ed_list

CVE-2017-7377

9pfs: host memory leakage via v9fs_create

CVE-2017-7493

Improper access control issues in the host directory sharing via
9pfs support.

CVE-2017-7980

Heap-based buffer overflow in the Cirrus VGA device that could allow
local guest OS users to execute arbitrary code or cause a denial of
service

CVE-2017-8086

9pfs: host memory leakage via v9pfs_list_xattr

CVE-2017-8112

Infinite loop in the VMWare PVSCSI emulation

CVE-2017-8309 / CVE-2017-8379

Host memory leakage issues via the audio capture buffer and the
keyboard input event handlers

CVE-2017-9330

Infinite loop due to incorrect return value in USB OHCI that may
result in denial of service

CVE-2017-9373 / CVE-2017-9374

Host memory leakage during hot unplug in IDE AHCI and USB emulated
devices that could result in denial of service

CVE-2017-9503

Null pointer dereference while processing megasas command

CVE-2017-10806

Stack buffer overflow in USB redirector

CVE-2017-10911

Xen disk may leak stack data via response ring

CVE-2017-11434

Out-of-bounds read while parsing Slirp/DHCP options

CVE-2017-14167

Out-of-bounds access while processing multiboot headers that could
result in the execution of arbitrary code

CVE-2017-15038

9pfs: information disclosure when reading extended attributes

CVE-2017-15289

Out-of-bounds write access issue in the Cirrus graphic adaptor that
could result in denial of service

CVE-2017-16845

Information leak in the PS/2 mouse and keyboard emulation support that
could be exploited during instance migration

CVE-2017-18043

Integer overflow in the macro ROUND_UP (n, d) that could result in
denial of service

CVE-2018-7550

Incorrect handling of memory during multiboot that could may result in
execution of arbitrary code");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u7", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}