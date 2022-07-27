# OpenVAS Vulnerability Test
# $Id: deb_3469.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3469-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703469");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2015-7295", "CVE-2015-7504", "CVE-2015-7512", "CVE-2015-8345",
                  "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8743", "CVE-2016-1568",
                  "CVE-2016-1714", "CVE-2016-1922");
  script_name("Debian Security Advisory DSA 3469-1 (qemu - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-02-08 00:00:00 +0100 (Mon, 08 Feb 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3469.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"qemu on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 1.1.2+dfsg-6a+deb7u12.

We recommend that you upgrade your qemu packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in qemu, a full virtualization solution on x86 hardware.

CVE-2015-7295
Jason Wang of Red Hat Inc. discovered that the Virtual Network
Device support is vulnerable to denial-of-service (via resource
exhaustion), that could occur when receiving large packets.

CVE-2015-7504
Qinghao Tang of Qihoo 360 Inc. and Ling Liu of Qihoo 360 Inc.
discovered that the PC-Net II ethernet controller is vulnerable to
a heap-based buffer overflow that could result in
denial-of-service (via application crash) or arbitrary code
execution.

CVE-2015-7512
Ling Liu of Qihoo 360 Inc. and Jason Wang of Red Hat Inc.
discovered that the PC-Net II ethernet controller is vulnerable to
a buffer overflow that could result in denial-of-service (via
application crash) or arbitrary code execution.

CVE-2015-8345
Qinghao Tang of Qihoo 360 Inc. discovered that the eepro100
emulator contains a flaw that could lead to an infinite loop when
processing Command Blocks, eventually resulting in
denial-of-service (via application crash).

CVE-2015-8504
Lian Yihan of Qihoo 360 Inc. discovered that the VNC display
driver support is vulnerable to an arithmetic exception flaw that
could lead to denial-of-service (via application crash).

CVE-2015-8558
Qinghao Tang of Qihoo 360 Inc. discovered that the USB EHCI
emulation support contains a flaw that could lead to an infinite
loop during communication between the host controller and a device
driver. This could lead to denial-of-service (via resource
exhaustion).

CVE-2015-8743
Ling Liu of Qihoo 360 Inc. discovered that the NE2000 emulator is
vulnerable to an out-of-bound read/write access issue, potentially
resulting in information leak or memory corruption.

CVE-2016-1568
Qinghao Tang of Qihoo 360 Inc. discovered that the IDE AHCI
emulation support is vulnerable to a use-after-free issue, that
could lead to denial-of-service (via application crash) or
arbitrary code execution.

CVE-2016-1714
Donghai Zhu of Alibaba discovered that the Firmware Configuration
emulation support is vulnerable to an out-of-bound read/write
access issue, that could lead to denial-of-service (via
application crash) or arbitrary code execution.

CVE-2016-1922
Ling Liu of Qihoo 360 Inc. discovered that 32-bit Windows guests
support is vulnerable to a null pointer dereference issue, that
could lead to denial-of-service (via application crash).");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6a+deb7u12", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6a+deb7u12", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6a+deb7u12", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6a+deb7u12", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6a+deb7u12", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6a+deb7u12", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}