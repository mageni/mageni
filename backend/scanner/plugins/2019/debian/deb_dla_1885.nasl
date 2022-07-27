# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891885");
  script_version("2019-08-16T08:19:10+0000");
  script_cve_id("CVE-2017-18509", "CVE-2018-20836", "CVE-2018-20856", "CVE-2018-5995", "CVE-2019-10207", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-1125", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-3882", "CVE-2019-3900");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-08-16 08:19:10 +0000 (Fri, 16 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-15 02:00:08 +0000 (Thu, 15 Aug 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1885-1] linux-4.9 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1885-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-4.9'
  package(s) announced via the DSA-1885-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-18509

Denis Andzakovic reported a missing type check in the IPv4 multicast
routing implementation. A user with the CAP_NET_ADMIN capability (in
any user namespace) could use this for denial-of-service (memory
corruption or crash) or possibly for privilege escalation.

CVE-2018-5995

ADLab of VenusTech discovered that the kernel logged the virtual
addresses assigned to per-CPU data, which could make it easier to
exploit other vulnerabilities.

CVE-2018-20836

chenxiang reported a race condition in libsas, the kernel
subsystem supporting Serial Attached SCSI (SAS) devices, which
could lead to a use-after-free. It is not clear how this might be
exploited.

CVE-2018-20856

Xiao Jin reported a potential double-free in the block subsystem,
in case an error occurs while initialising the I/O scheduler for a
block device. It is not clear how this might be exploited.

CVE-2019-1125

It was discovered that most x86 processors could speculatively
skip a conditional SWAPGS instruction used when entering the
kernel from user mode, and/or could speculatively execute it when
it should be skipped. This is a subtype of Spectre variant 1,
which could allow local users to obtain sensitive information from
the kernel or other processes. It has been mitigated by using
memory barriers to limit speculative execution. Systems using an
i386 kernel are not affected as the kernel does not use SWAPGS.

CVE-2019-3882

It was found that the vfio implementation did not limit the number
of DMA mappings to device memory. A local user granted ownership
of a vfio device could use this to cause a denial of service
(out-of-memory condition).

CVE-2019-3900

It was discovered that vhost drivers did not properly control the
amount of work done to service requests from guest VMs. A
malicious guest could use this to cause a denial-of-service
(unbounded CPU usage) on the host.

CVE-2019-10207

The syzkaller tool found a potential null dereference in various
drivers for UART-attached Bluetooth adapters. A local user with
access to a pty device or other suitable tty device could use this
for denial-of-service (BUG/oops).

CVE-2019-10638

Amit Klein and Benny Pinkas discovered that the generation of IP
packet IDs used a weak hash function, 'jhash'. This could enable
tracking individual computers as they communicate with different
remote servers and from different networks. The 'siphash'
function is now used instead.

CVE-2019-10639

Amit Klein and Benny Pinkas discovered that the generation of IP
packet  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.9.168-1+deb9u5~deb8u1.

We recommend that you upgrade your linux-4.9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-arm", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-686", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-armel", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-armhf", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-i386", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-armmp", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-common", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-common-rt", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-marvell", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-rt-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-686", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-armel", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-armhf", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-i386", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-armmp", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-armmp-lpae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-common", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-common-rt", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-marvell", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-rt-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-rt-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-686", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-all", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-all-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-all-armel", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-all-armhf", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-all-i386", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-armmp", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-armmp-lpae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-common", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-common-rt", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-marvell", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-rt-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.9-rt-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-amd64-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-armmp", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-armmp-lpae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-marvell", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686-pae-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-amd64-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-armmp", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-armmp-lpae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-marvell", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-686-pae-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-amd64-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-686", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-686-pae-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-amd64-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-armmp", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-armmp-lpae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-marvell", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-rt-686-pae", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-rt-686-pae-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-rt-amd64", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.9-rt-amd64-dbg", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.7", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.8", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.9", ver:"4.9.168-1+deb9u5~deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);