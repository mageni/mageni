# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.705191");
  script_version("2022-07-28T10:10:25+0000");
  script_cve_id("CVE-2021-33655", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33743", "CVE-2022-33744", "CVE-2022-34918");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-07-28 10:10:25 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 14:00:00 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-28 01:00:21 +0000 (Thu, 28 Jul 2022)");
  script_name("Debian: Security Advisory for linux (DSA-5191-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5191.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5191-1");
  script_xref(name:"Advisory-ID", value:"DSA-5191-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-5191-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may
lead to privilege escalation, denial of service or information leaks:

CVE-2021-33655
A user with access to a framebuffer console driver could cause a
memory out-of-bounds write via the FBIOPUT_VSCREENINFO ioctl.

CVE-2022-2318
A use-after-free in the Amateur Radio X.25 PLP (Rose) support may
result in denial of service.

CVE-2022-26365,
CVE-2022-33740,
CVE-2022-33741,
CVE-2022-33742
Roger Pau Monne discovered that Xen block and network PV device
frontends don't zero out memory regions before sharing them with the
backend, which may result in information disclosure. Additionally it
was discovered that the granularity of the grant table doesn't permit
sharing less than a 4k page, which may also result in information
disclosure.

CVE-2022-33743
Jan Beulich discovered that incorrect memory handling in the Xen
network backend may lead to denial of service.

CVE-2022-33744
Oleksandr Tyshchenko discovered that ARM Xen guests can cause a denial
of service to the Dom0 via paravirtual devices.

CVE-2022-34918
Arthur Mongodin discovered a heap buffer overflow in the Netfilter
subsystem which may result in local privilege escalation.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 5.10.127-2.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bpftool", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"efi-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"efi-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-arm", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-s390", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-x86", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-4kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-5kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-686", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-686-pae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-amd64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-arm64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-armmp-lpae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-cloud-amd64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-cloud-arm64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-common", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-common-rt", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-loongson-3", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-marvell", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-octeon", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-powerpc64le", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-rpi", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-rt-686-pae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-rt-amd64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-rt-arm64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-rt-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-13-s390x", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-4kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-5kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-686", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-686-pae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-amd64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-arm64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-armmp-lpae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-cloud-amd64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-cloud-arm64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-common", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-common-rt", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-loongson-3", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-marvell", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-octeon", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-powerpc64le", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-rpi", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-rt-686-pae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-rt-amd64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-rt-arm64", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-rt-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-16-s390x", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp-lpae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-loongson-3", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-marvell", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-octeon", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rpi", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rt-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-s390x", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-4kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-4kc-malta-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-5kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-5kc-malta-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-686-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-686-pae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-686-pae-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-686-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-amd64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-arm64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-armmp-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-armmp-lpae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-armmp-lpae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-cloud-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-cloud-amd64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-cloud-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-cloud-arm64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-loongson-3", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-loongson-3-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-marvell", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-marvell-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-octeon", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-octeon-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-powerpc64le", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-powerpc64le-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rpi", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rpi-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rt-686-pae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rt-686-pae-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rt-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rt-amd64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rt-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rt-arm64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rt-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-rt-armmp-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-s390x", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-13-s390x-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-4kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-4kc-malta-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-5kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-5kc-malta-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-686-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-686-pae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-686-pae-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-686-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-amd64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-arm64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-armmp-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-armmp-lpae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-armmp-lpae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-cloud-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-cloud-amd64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-cloud-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-cloud-arm64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-loongson-3", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-loongson-3-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-marvell", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-marvell-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-octeon", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-octeon-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-powerpc64le", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-powerpc64le-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rpi", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rpi-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rt-686-pae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rt-686-pae-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rt-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rt-amd64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rt-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rt-arm64-unsigned", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rt-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-rt-armmp-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-s390x", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-16-s390x-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-pae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-686-pae-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-amd64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-arm64-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x-dbg", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-13", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-16", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"serial-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"serial-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-13-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-13-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-16-armmp-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-16-marvell-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-13-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-13-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-13-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-13-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-13-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-13-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-16-4kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-16-5kc-malta-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-16-loongson-3-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-16-octeon-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-16-powerpc64le-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-16-s390x-di", ver:"5.10.127-2", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
