# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892623");
  script_version("2021-04-11T03:00:11+0000");
  script_cve_id("CVE-2020-17380", "CVE-2020-25085", "CVE-2021-20203", "CVE-2021-20255", "CVE-2021-20257", "CVE-2021-3392", "CVE-2021-3409", "CVE-2021-3416");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-12 10:16:30 +0000 (Mon, 12 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-11 03:00:11 +0000 (Sun, 11 Apr 2021)");
  script_name("Debian LTS: Security Advisory for qemu (DLA-2623-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2623-1");
  script_xref(name:"Advisory-ID", value:"DLA-2623-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/984450");
  script_xref(name:"URL", value:"https://bugs.debian.org/984451");
  script_xref(name:"URL", value:"https://bugs.debian.org/984452");
  script_xref(name:"URL", value:"https://bugs.debian.org/984448");
  script_xref(name:"URL", value:"https://bugs.debian.org/984449");
  script_xref(name:"URL", value:"https://bugs.debian.org/970937");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the DLA-2623-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in QEMU, a fast processor
emulator.

CVE-2021-20257

net: e1000: infinite loop while processing transmit descriptors

CVE-2021-20255

A stack overflow via an infinite recursion vulnerability was found in the
eepro100 i8255x device emulator of QEMU. This issue occurs while processing
controller commands due to a DMA reentry issue. This flaw allows a guest
user or process to consume CPU cycles or crash the QEMU process on the
host, resulting in a denial of service.

CVE-2021-20203

An integer overflow issue was found in the vmxnet3 NIC emulator of the
QEMU. It may occur if a guest was to supply invalid values for rx/tx queue
size or other NIC parameters. A privileged guest user may use this flaw to
crash the QEMU process on the host resulting in DoS scenario.

CVE-2021-3416

A potential stack overflow via infinite loop issue was found in various NIC
emulators of QEMU in versions up to and including 5.2.0. The issue occurs
in loopback mode of a NIC wherein reentrant DMA checks get bypassed. A
guest user/process may use this flaw to consume CPU cycles or crash the
QEMU process on the host resulting in DoS scenario.

CVE-2021-3416

The patch for CVE-2020-17380/CVE-2020-25085 was found to be ineffective,
thus making QEMU vulnerable to the out-of-bounds read/write access issues
previously found in the SDHCI controller emulation code. This flaw allows a
malicious privileged guest to crash the QEMU process on the host, resulting
in a denial of service or potential code execution.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:2.8+dfsg-6+deb9u14.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-block-extra", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.8+dfsg-6+deb9u14", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
