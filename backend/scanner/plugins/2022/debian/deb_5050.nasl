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
  script_oid("1.3.6.1.4.1.25623.1.0.705050");
  script_version("2022-01-22T02:00:23+0000");
  script_cve_id("CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-39685", "CVE-2021-4155", "CVE-2021-45095", "CVE-2021-45469", "CVE-2021-45480", "CVE-2022-0185", "CVE-2022-23222");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-01-24 11:12:31 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-22 02:00:23 +0000 (Sat, 22 Jan 2022)");
  script_name("Debian: Security Advisory for linux (DSA-5050-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5050.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5050-1");
  script_xref(name:"Advisory-ID", value:"DSA-5050-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-5050-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2021-4155
Kirill Tkhai discovered a data leak in the way the XFS_IOC_ALLOCSP
IOCTL in the XFS filesystem allowed for a size increase of files
with unaligned size. A local attacker can take advantage of this
flaw to leak data on the XFS filesystem.

CVE-2021-28711, CVE-2021-28712, CVE-2021-28713 (XSA-391)

Juergen Gross reported that malicious PV backends can cause a denial
of service to guests being serviced by those backends via high
frequency events, even if those backends are running in a less
privileged environment.

CVE-2021-28714, CVE-2021-28715 (XSA-392)

Juergen Gross discovered that Xen guests can force the Linux
netback driver to hog large amounts of kernel memory, resulting in
denial of service.

CVE-2021-39685
Szymon Heidrich discovered a buffer overflow vulnerability in the
USB gadget subsystem, resulting in information disclosure, denial of
service or privilege escalation.

CVE-2021-45095
It was discovered that the Phone Network protocol (PhoNet) driver
has a reference count leak in the pep_sock_accept() function.

CVE-2021-45469
Wenqing Liu reported an out-of-bounds memory access in the f2fs
implementation if an inode has an invalid last xattr entry. An
attacker able to mount a specially crafted image can take advantage
of this flaw for denial of service.

CVE-2021-45480
A memory leak flaw was discovered in the __rds_conn_create()
function in the RDS (Reliable Datagram Sockets) protocol subsystem.

CVE-2022-0185
William Liu, Jamie Hill-Daniel, Isaac Badipe, Alec Petridis, Hrvoje
Misetic and Philip Papurt discovered a heap-based buffer overflow
flaw in the legacy_parse_param function in the Filesystem Context
functionality, allowing an local user (with CAP_SYS_ADMIN capability
in the current namespace) to escalate privileges.

CVE-2022-23222
tr3e discovered that the BPF verifier does not properly restrict
several *_OR_NULL pointer types allowing these types to do pointer
arithmetic. A local user with the ability to call bpf(), can take
advantage of this flaw to excalate privileges. Unprivileged calls to
bpf() are disabled by default in Debian, mitigating this flaw.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 5.10.92-1. This version includes changes which were aimed to
land in the next Debian bullseye point release.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"affs-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ata-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bpftool", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crc-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"efi-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"efi-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"event-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fat-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fb-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"input-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kernel-image-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"leds-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-arm", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-s390", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-10-x86", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-4kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-5kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-686", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-686-pae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-amd64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-arm64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-armmp-lpae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-cloud-amd64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-cloud-arm64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-common", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-common-rt", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-loongson-3", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-marvell", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-octeon", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-powerpc64le", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-rpi", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-rt-686-pae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-rt-amd64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-rt-arm64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-rt-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-10-s390x", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-4kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-5kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-686", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-686-pae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-amd64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-arm64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-armmp-lpae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-cloud-amd64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-cloud-arm64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-common", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-common-rt", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-loongson-3", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-marvell", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-octeon", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-powerpc64le", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-rpi", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-rt-686-pae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-rt-amd64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-rt-arm64", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-rt-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-9-s390x", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp-lpae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-loongson-3", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-marvell", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-octeon", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rpi", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rt-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-s390x", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-4kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-4kc-malta-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-5kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-5kc-malta-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-686-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-686-pae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-686-pae-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-686-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-amd64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-arm64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-armmp-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-armmp-lpae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-armmp-lpae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-cloud-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-cloud-amd64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-cloud-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-cloud-arm64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-loongson-3", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-loongson-3-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-marvell", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-marvell-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-octeon", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-octeon-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-powerpc64le", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-powerpc64le-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rpi", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rpi-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rt-686-pae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rt-686-pae-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rt-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rt-amd64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rt-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rt-arm64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rt-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-rt-armmp-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-s390x", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-10-s390x-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-4kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-4kc-malta-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-5kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-5kc-malta-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-686-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-686-pae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-686-pae-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-686-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-amd64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-arm64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-armmp-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-armmp-lpae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-armmp-lpae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-cloud-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-cloud-amd64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-cloud-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-cloud-arm64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-loongson-3", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-loongson-3-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-marvell", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-marvell-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-octeon", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-octeon-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-powerpc64le", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-powerpc64le-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rpi", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rpi-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rt-686-pae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rt-686-pae-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rt-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rt-amd64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rt-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rt-arm64-unsigned", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rt-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-rt-armmp-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-s390x", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-9-s390x-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-pae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-686-pae-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-amd64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-arm64-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x-dbg", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-10", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-9", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"loop-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"md-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"minix-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pata-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"rtc-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sata-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"serial-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"serial-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sound-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udf-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-10-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-10-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-9-armmp-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-9-marvell-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-10-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-10-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-10-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-10-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-10-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-10-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-9-4kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-9-5kc-malta-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-9-loongson-3-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-9-octeon-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-9-powerpc64le-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-5.10.0-9-s390x-di", ver:"5.10.92-1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
