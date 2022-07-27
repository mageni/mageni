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
  script_oid("1.3.6.1.4.1.25623.1.0.892560");
  script_version("2021-02-19T07:31:47+0000");
  script_cve_id("CVE-2020-15469", "CVE-2020-15859", "CVE-2020-25084", "CVE-2020-28916", "CVE-2020-29130", "CVE-2020-29443", "CVE-2021-20181", "CVE-2021-20221");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-19 11:47:28 +0000 (Fri, 19 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-19 04:00:28 +0000 (Fri, 19 Feb 2021)");
  script_name("Debian LTS: Security Advisory for qemu (DLA-2560-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00024.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2560-1");
  script_xref(name:"Advisory-ID", value:"DLA-2560-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/970253");
  script_xref(name:"URL", value:"https://bugs.debian.org/965978");
  script_xref(name:"URL", value:"https://bugs.debian.org/970539");
  script_xref(name:"URL", value:"https://bugs.debian.org/974687");
  script_xref(name:"URL", value:"https://bugs.debian.org/976388");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the DLA-2560-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in QEMU, a fast processor
emulator (notably used in KVM and Xen HVM virtualization). An attacker
could trigger a denial-of-service (DoS), information leak, and
possibly execute arbitrary code with the privileges of the QEMU
process on the host.

CVE-2020-15469

A MemoryRegionOps object may lack read/write callback methods,
leading to a NULL pointer dereference.

CVE-2020-15859

QEMU has a use-after-free in hw/net/e1000e_core.c because a guest
OS user can trigger an e1000e packet with the data's address set
to the e1000e's MMIO address.

CVE-2020-25084

QEMU has a use-after-free in hw/usb/hcd-xhci.c because the
usb_packet_map return value is not checked.

CVE-2020-28916

hw/net/e1000e_core.c has an infinite loop via an RX descriptor
with a NULL buffer address.

CVE-2020-29130

slirp.c has a buffer over-read because it tries to read a certain
amount of header data even if that exceeds the total packet
length.

CVE-2020-29443

ide_atapi_cmd_reply_end in hw/ide/atapi.c allows out-of-bounds
read access because a buffer index is not validated.

CVE-2021-20181

9pfs: ZDI-CAN-10904: QEMU Plan 9 file system TOCTOU privilege
escalation vulnerability.

CVE-2021-20221

aarch64: GIC: out-of-bound heap buffer access via an interrupt ID
field.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:2.8+dfsg-6+deb9u13.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-block-extra", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.8+dfsg-6+deb9u13", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
