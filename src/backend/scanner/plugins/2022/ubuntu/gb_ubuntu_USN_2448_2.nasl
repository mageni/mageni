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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2014.2448.2");
  script_cve_id("CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-7825", "CVE-2014-7826", "CVE-2014-7970", "CVE-2014-8086", "CVE-2014-8134", "CVE-2014-8369", "CVE-2014-9090");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 19:37:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-2448-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.10");

  script_xref(name:"Advisory-ID", value:"USN-2448-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2448-2");
  script_xref(name:"URL", value:"http://bugs.launchpad.net/bugs/1390604");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2448-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2448-1 fixed vulnerabilities in the Linux kernel. Due to an unrelated
regression TCP Throughput drops to zero for several drivers after upgrading.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 An information leak in the Linux kernel was discovered that could leak the
 high 16 bits of the kernel stack address on 32-bit Kernel Virtual Machine
 (KVM) paravirt guests. A user in the guest OS could exploit this leak to
 obtain information that could potentially be used to aid in attacking the
 kernel. (CVE-2014-8134)

 Rabin Vincent, Robert Swiecki, Russell King discovered that the ftrace
 subsystem of the Linux kernel does not properly handle private syscall
 numbers. A local user could exploit this flaw to cause a denial of service
 (OOPS). (CVE-2014-7826)

 A flaw in the handling of malformed ASCONF chunks by SCTP (Stream Control
 Transmission Protocol) implementation in the Linux kernel was discovered. A
 remote attacker could exploit this flaw to cause a denial of service
 (system crash). (CVE-2014-3673)

 A flaw in the handling of duplicate ASCONF chunks by SCTP (Stream Control
 Transmission Protocol) implementation in the Linux kernel was discovered. A
 remote attacker could exploit this flaw to cause a denial of service
 (panic). (CVE-2014-3687)

 It was discovered that excessive queuing by SCTP (Stream Control
 Transmission Protocol) implementation in the Linux kernel can cause memory
 pressure. A remote attacker could exploit this flaw to cause a denial of
 service. (CVE-2014-3688)

 Rabin Vincent, Robert Swiecki, Russell Kinglaw discovered a flaw in how the
 perf subsystem of the Linux kernel handles private systecall numbers. A
 local user could exploit this to cause a denial of service (OOPS) or bypass
 ASLR protections via a crafted application. (CVE-2014-7825)

 Andy Lutomirski discovered a flaw in how the Linux kernel handles
 pivot_root when used with a chroot directory. A local user could exploit
 this flaw to cause a denial of service (mount-tree loop). (CVE-2014-7970)

 Dmitry Monakhov discovered a race condition in the ext4_file_write_iter
 function of the Linux kernel's ext4 filesystem. A local user could exploit
 this flaw to cause a denial of service (file unavailability).
 (CVE-2014-8086)

 The KVM (kernel virtual machine) subsystem of the Linux kernel
 miscalculates the number of memory pages during the handling of a mapping
 failure. A guest OS user could exploit this to cause a denial of service
 (host OS page unpinning) or possibly have unspecified other impact by
 leveraging guest OS privileges. (CVE-2014-8369)

 Andy Lutomirski discovered that the Linux kernel does not properly handle
 faults associated with the Stack Segment (SS) register on the x86
 architecture. A local attacker could exploit this flaw to cause a denial of
 service (panic). (CVE-2014-9090)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.10.");

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

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-28-generic-lpae", ver:"3.16.0-28.38", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-28-generic", ver:"3.16.0-28.38", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-28-lowlatency", ver:"3.16.0-28.38", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-28-powerpc-e500mc", ver:"3.16.0-28.38", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-28-powerpc-smp", ver:"3.16.0-28.38", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-28-powerpc64-emb", ver:"3.16.0-28.38", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-28-powerpc64-smp", ver:"3.16.0-28.38", rls:"UBUNTU14.10"))) {
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
