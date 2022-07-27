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
  script_oid("1.3.6.1.4.1.25623.1.0.705173");
  script_version("2022-07-05T08:13:05+0000");
  script_cve_id("CVE-2021-4197", "CVE-2022-0494", "CVE-2022-0812", "CVE-2022-0854", "CVE-2022-1011", "CVE-2022-1012", "CVE-2022-1016", "CVE-2022-1048", "CVE-2022-1184", "CVE-2022-1195", "CVE-2022-1198", "CVE-2022-1199", "CVE-2022-1204", "CVE-2022-1205", "CVE-2022-1353", "CVE-2022-1419", "CVE-2022-1516", "CVE-2022-1652", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-2153", "CVE-2022-23960", "CVE-2022-26490", "CVE-2022-27666", "CVE-2022-28356", "CVE-2022-28388", "CVE-2022-28389", "CVE-2022-28390", "CVE-2022-29581", "CVE-2022-30594", "CVE-2022-32250", "CVE-2022-32296", "CVE-2022-33981");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-07-05 08:13:05 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-05 01:00:33 +0000 (Tue, 05 Jul 2022)");
  script_name("Debian: Security Advisory for linux (DSA-5173-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5173.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5173-1");
  script_xref(name:"Advisory-ID", value:"DSA-5173-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-5173-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2021-4197
Eric Biederman reported that incorrect permission checks in the
cgroup process migration implementation can allow a local attacker
to escalate privileges.

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

CVE-2022-1012,
CVE-2022-32296
Moshe Kol, Amit Klein, and Yossi Gilad discovered a weakness
in randomisation of TCP source port selection.

CVE-2022-1016
David Bouman discovered a flaw in the netfilter subsystem where
the nft_do_chain function did not initialize register data that
nf_tables expressions can read from and write to. A local attacker
can take advantage of this to read sensitive information.

CVE-2022-1048
Hu Jiahui discovered a race condition in the sound subsystem that
can result in a use-after-free. A local user permitted to access a
PCM sound device can take advantage of this flaw to crash the
system or potentially for privilege escalation.

CVE-2022-1184
A flaw was discovered in the ext4 filesystem driver which can lead
to a use-after-free. A local user permitted to mount arbitrary
filesystems could exploit this to cause a denial of service (crash
or memory corruption) or possibly for privilege escalation.

CVE-2022-1195
Lin Ma discovered race conditions in the 6pack and mkiss hamradio
drivers, which could lead to a use-after-free. A local user could
exploit these to cause a denial of service (memory corruption or
crash) or possibly for privilege escalation.

CVE-2022-1198
Duoming Zhou discovered a race condition in the 6pack hamradio
driver, which could lead to a use-after-free. A local user could
exploit this to cause a denial of service (memory corruption or
crash) or possibly for privilege escalation.

CVE-2022-1199,
CVE-2022-1204,
CVE-2022-1205
Duoming Zhou discovered race conditions in the AX.25 hamradio
protocol ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), these problems have been
fixed in version 4.19.249-2.

Due to an issue in the signing service (Cf. Debian bug #1012741), the
vport-vxlan module cannot be loaded for the signed kernel for amd64 in
this update.

This update also corrects a regression in the network scheduler
subsystem (bug #1013299).

For the 32-bit Arm (armel and armhf) architectures, this update
enables optimised implementations of several cryptographic and CRC
algorithms. For at least AES, this should remove a timing sidechannel
that could lead to a leak of sensitive information.

This update includes many more bug fixes from stable updates
4.19.236-4.19.249 inclusive, including for bug #1006346. The random
driver has been backported from Linux 5.19, fixing numerous
performance and correctness issues. Some changes will be visible:

The entropy pool size is now 256 bits instead of 4096. You may need
to adjust the configuration of system monitoring or user-space
entropy gathering services to allow for this.On systems without a hardware RNG, the kernel may log more uses of
/dev/urandom before it is fully initialised. These uses were
previously under-counted and this is not a regression.
We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbpf-dev", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbpf4.19", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-arm", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-s390", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-8-x86", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-config-4.19", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.19", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-4kc-malta", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-5kc-malta", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-686", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-686-pae", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-amd64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-arm64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-armel", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-armhf", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-i386", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-mips", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-mips64el", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-mipsel", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-ppc64el", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-all-s390x", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-amd64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-arm64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-armmp", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-armmp-lpae", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-cloud-amd64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-common", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-common-rt", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-loongson-3", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-marvell", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-octeon", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-powerpc64le", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rpi", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-686-pae", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-amd64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-arm64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-rt-armmp", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-19-s390x", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-4kc-malta", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-5kc-malta", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-686", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-686-pae", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-amd64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-arm64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-armel", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-armhf", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-i386", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-mips", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-mips64el", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-mipsel", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-ppc64el", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-all-s390x", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-amd64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-arm64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-armmp", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-armmp-lpae", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-cloud-amd64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-common", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-common-rt", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-loongson-3", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-marvell", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-octeon", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-powerpc64le", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-rpi", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-rt-686-pae", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-rt-amd64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-rt-arm64", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-rt-armmp", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.19.0-21-s390x", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-4kc-malta", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-4kc-malta-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-5kc-malta", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-5kc-malta-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-pae-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-pae-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-686-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-amd64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-amd64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-arm64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-arm64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-lpae", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-armmp-lpae-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-cloud-amd64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-cloud-amd64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-loongson-3", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-loongson-3-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-marvell", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-marvell-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-octeon", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-octeon-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-powerpc64le", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-powerpc64le-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rpi", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rpi-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-686-pae-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-686-pae-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-amd64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-amd64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-arm64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-arm64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-armmp", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-rt-armmp-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-s390x", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-19-s390x-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-4kc-malta", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-4kc-malta-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-5kc-malta", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-5kc-malta-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-686-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-686-pae-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-686-pae-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-686-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-amd64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-amd64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-arm64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-arm64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-armmp", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-armmp-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-armmp-lpae", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-armmp-lpae-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-cloud-amd64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-cloud-amd64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-loongson-3", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-loongson-3-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-marvell", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-marvell-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-octeon", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-octeon-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-powerpc64le", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-powerpc64le-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rpi", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rpi-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rt-686-pae-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rt-686-pae-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rt-amd64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rt-amd64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rt-arm64-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rt-arm64-unsigned", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rt-armmp", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-rt-armmp-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-s390x", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.19.0-21-s390x-dbg", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.19", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.19", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.19", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-19", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.19.0-21", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"4.19.249-2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
