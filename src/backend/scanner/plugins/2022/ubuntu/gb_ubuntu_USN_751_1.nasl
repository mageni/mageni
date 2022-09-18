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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.751.1");
  script_cve_id("CVE-2008-4307", "CVE-2008-6107", "CVE-2009-0028", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0605", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859", "CVE-2009-1046");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-751-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(7\.10|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-751-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-751-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.22' package(s) announced via the USN-751-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NFS did not correctly handle races between fcntl and interrupts. A local
attacker on an NFS mount could consume unlimited kernel memory, leading to
a denial of service. Ubuntu 8.10 was not affected. (CVE-2008-4307)

Sparc syscalls did not correctly check mmap regions. A local attacker
could cause a system panic, leading to a denial of service. Ubuntu 8.10
was not affected. (CVE-2008-6107)

In certain situations, cloned processes were able to send signals to parent
processes, crossing privilege boundaries. A local attacker could send
arbitrary signals to parent processes, leading to a denial of service.
(CVE-2009-0028)

The kernel keyring did not free memory correctly. A local attacker could
consume unlimited kernel memory, leading to a denial of service.
(CVE-2009-0031)

The SCTP stack did not correctly validate FORWARD-TSN packets. A remote
attacker could send specially crafted SCTP traffic causing a system crash,
leading to a denial of service. (CVE-2009-0065)

The eCryptfs filesystem did not correctly handle certain VFS return codes.
A local attacker with write-access to an eCryptfs filesystem could cause a
system crash, leading to a denial of service. (CVE-2009-0269)

The Dell platform device did not correctly validate user parameters. A
local attacker could perform specially crafted reads to crash the system,
leading to a denial of service. (CVE-2009-0322)

The page fault handler could consume stack memory. A local attacker could
exploit this to crash the system or gain root privileges with a Kprobe
registered. Only Ubuntu 8.10 was affected. (CVE-2009-0605)

Network interfaces statistics for the SysKonnect FDDI driver did not check
capabilities. A local user could reset statistics, potentially interfering
with packet accounting systems. (CVE-2009-0675)

The getsockopt function did not correctly clear certain parameters. A local
attacker could read leaked kernel memory, leading to a loss of privacy.
(CVE-2009-0676)

The ext4 filesystem did not correctly clear group descriptors when
resizing. A local attacker could exploit this to crash the system, leading
to a denial of service. (CVE-2009-0745)

The ext4 filesystem did not correctly validate certain fields. A local
attacker could mount a malicious ext4 filesystem, causing a system
crash, leading to a denial of service. (CVE-2009-0746, CVE-2009-0747,
CVE-2009-0748)

The syscall interface did not correctly validate parameters when crossing
the 64-bit/32-bit boundary. A local attacker could bypass certain syscall
restricts via crafted syscalls. (CVE-2009-0834, CVE-2009-0835)

The shared memory subsystem did not correctly handle certain shmctl calls
when CONFIG_SHMEM was disabled. Ubuntu kernels were not vulnerable, since
CONFIG_SHMEM is enabled by default. (CVE-2009-0859)

The virtual consoles did not correctly handle certain UTF-8 sequences. A
local attacker on the physical console could exploit this to cause a system
crash, leading to a denial of service. (CVE-2009-1046)");

  script_tag(name:"affected", value:"'linux, linux-source-2.6.22' package(s) on Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-386", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-cell", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-generic", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-hppa32", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-hppa64", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-itanium", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-lpia", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-lpiacompat", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-mckinley", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-powerpc-smp", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-powerpc", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-powerpc64-smp", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-rt", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-server", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-sparc64-smp", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-sparc64", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-ume", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-virtual", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-16-xen", ver:"2.6.22-16.62", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-386", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-generic", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-hppa32", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-hppa64", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-itanium", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-lpia", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-lpiacompat", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-mckinley", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-openvz", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-powerpc-smp", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-powerpc", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-powerpc64-smp", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-rt", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-server", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-sparc64-smp", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-sparc64", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-virtual", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.24-23-xen", ver:"2.6.24-23.52", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-11-generic", ver:"2.6.27-11.31", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-11-server", ver:"2.6.27-11.31", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.27-11-virtual", ver:"2.6.27-11.31", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
