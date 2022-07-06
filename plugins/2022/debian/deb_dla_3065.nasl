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
  script_oid("1.3.6.1.4.1.25623.1.0.893065");
  script_version("2022-07-05T06:03:56+0000");
  script_cve_id("CVE-2018-1108", "CVE-2021-39713", "CVE-2021-4149", "CVE-2022-0494", "CVE-2022-0812", "CVE-2022-0854", "CVE-2022-1011", "CVE-2022-1012", "CVE-2022-1016", "CVE-2022-1198", "CVE-2022-1199", "CVE-2022-1353", "CVE-2022-1516", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-2153", "CVE-2022-23036", "CVE-2022-23037", "CVE-2022-23038", "CVE-2022-23039", "CVE-2022-23040", "CVE-2022-23041", "CVE-2022-23042", "CVE-2022-23960", "CVE-2022-24958", "CVE-2022-26490", "CVE-2022-26966", "CVE-2022-27223", "CVE-2022-28356", "CVE-2022-28390", "CVE-2022-30594", "CVE-2022-32250", "CVE-2022-32296", "CVE-2022-33981");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-05 06:03:56 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 23:54:00 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-07-02 01:00:37 +0000 (Sat, 02 Jul 2022)");
  script_name("Debian LTS: Security Advisory for linux (DLA-3065-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/07/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3065-1");
  script_xref(name:"Advisory-ID", value:"DLA-3065-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/922204");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DLA-3065-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

This update is unfortunately not available for the armel architecture.

CVE-2018-1108

It was discovered that the random driver could generate random
bytes through /dev/random and the getrandom() system call before
gathering enough entropy that these would be unpredictable. This
could compromise the confidentiality and integrity of encrypted
communications.

The original fix for this issue had to be reverted because it
caused the boot process to hang on many systems. In this version,
the random driver has been updated, making it more effective in
gathering entropy without needing a hardware RNG.

CVE-2021-4149

Hao Sun reported a flaw in the Btrfs fileysstem driver. There
is a potential lock imbalance in an error path. A local user
might be able to exploit this for denial of service.

CVE-2021-39713

The syzbot tool found a race condition in the network scheduling
subsystem which could lead to a use-after-free. A local user
could exploit this for denial of service (memory corruption or
crash) or possibly for privilege escalation.

CVE-2022-0494

The scsi_ioctl() was susceptible to an information leak only
exploitable by users with CAP_SYS_ADMIN or CAP_SYS_RAWIO
capabilities.

CVE-2022-0812

It was discovered that the RDMA transport for NFS (xprtrdma)
miscalculated the size of message headers, which could lead to a
leak of sensitive information between NFS servers and clients.

CVE-2022-0854

Ali Haider discovered a potential information leak in the DMA
subsystem. On systems where the swiotlb feature is needed, this
might allow a local user to read sensitive information.

CVE-2022-1011

Jann Horn discovered a flaw in the FUSE (Filesystem in User-Space)
implementation. A local user permitted to mount FUSE filesystems
could exploit this to cause a use-after-free and read sensitive
information.

CVE-2022-1012, CVE-2022-32296

Moshe Kol, Amit Klein, and Yossi Gilad discovered a weakness
in randomisation of TCP source port selection.

CVE-2022-1016

David Bouman discovered a flaw in the netfilter subsystem where
the nft_do_chain function did not initialize register data that
nf_tables expressions can read from and write to. A local attacker
can take advantage of this to read sensitive information.

CVE-2022-1198

Duoming Zhou discovered a race condition in the 6pack hamradio
driver, which could lead to a use-after-free. A local user could
exploit this to cause a denial of service (memory corruption or
crash) or possibly for privilege escalation.

CVE-2022-1199

Duoming Zhou  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.9.320-2.

For the armhf architecture, this update enables optimised
implementations of several cryptographic and CRC algorithms. For at
least AES, this should remove a timing side-channel that could lead to
a leak of sensitive information.

This update includes many more bug fixes from stable updates
4.9.304-4.9.320 inclusive. The random driver has been backported from
Linux 5.19, fixing numerous performance and correctness issues. Some
changes will be visible:

- The entropy pool size is now 256 bits instead of 4096. You may need
to adjust the configuration of system monitoring or user-space
entropy gathering services to allow for this.

- On systems without a hardware RNG, the kernel will log many more
uses of /dev/urandom before it is fully initialised. These uses
were previously under-counted and this is not a regression.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libusbip-dev", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-arm", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-x86", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-686", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-686-pae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-all", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-all-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-all-arm64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-all-armel", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-all-armhf", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-all-i386", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-arm64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-armmp", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-armmp-lpae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-common", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-common-rt", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-marvell", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-rt-686-pae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-18-rt-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-686", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-686-pae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-all", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-all-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-all-arm64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-all-armhf", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-all-i386", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-arm64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-armmp", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-armmp-lpae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-common", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-common-rt", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-rt-686-pae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-19-rt-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-686", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-686-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-686-pae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-686-pae-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-amd64-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-arm64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-arm64-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-armmp", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-armmp-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-armmp-lpae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-armmp-lpae-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-marvell", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-marvell-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-rt-686-pae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-rt-686-pae-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-rt-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-18-rt-amd64-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-686", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-686-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-686-pae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-686-pae-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-amd64-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-arm64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-arm64-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-armmp", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-armmp-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-armmp-lpae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-armmp-lpae-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-rt-686-pae", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-rt-686-pae-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-rt-amd64", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-19-rt-amd64-dbg", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-18", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-19", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"4.9.320-2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
