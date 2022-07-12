# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1076");
  script_version("2020-01-23T15:42:05+0000");
  script_cve_id("CVE-2017-18360", "CVE-2018-10322", "CVE-2018-1092", "CVE-2018-1094", "CVE-2018-13094", "CVE-2018-14641", "CVE-2018-18281", "CVE-2018-18397", "CVE-2018-18559", "CVE-2018-19824", "CVE-2018-20511", "CVE-2018-5391", "CVE-2018-7740", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 15:42:05 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:30:14 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1076)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1076");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1076 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A security flaw was found in the ip_frag_reasm() function in net/ipv4/ip_fragment.c in the Linux kernel which can cause a later system crash in ip_do_fragment(). With certain non-default, but non-rare, configuration of a victim host, an attacker can trigger this crash remotely, thus leading to a remote denial of service.(CVE-2018-14641)

A flaw named FragmentSmack was found in the way the Linux kernel handled reassembly of fragmented IPv4 and IPv6 packets. A remote attacker could use this flaw to trigger time and calculation expensive fragment reassembly algorithm by sending specially crafted packets which could lead to a CPU saturation and hence a denial of service on the system.(CVE-2018-5391)

The resv_map_release function in mm/hugetlb.c in the Linux kernel, through 4.15.7, allows local users to cause a denial of service (BUG) via a crafted application that makes mmap system calls and has a large pgoff argument to the remap_file_pages system call. (CVE-2018-7740)

A use-after-free vulnerability was found in the way the Linux kernel's KVM hypervisor emulates a preemption timer for L2 guests when nested (=1) virtualization is enabled. This high resolution timer(hrtimer) runs when a L2 guest is active. After VM exit, the sync_vmcs12() timer object is stopped. The use-after-free occurs if the timer object is freed before calling sync_vmcs12() routine. A guest user/process could use this flaw to crash the host kernel resulting in a denial of service or, potentially, gain privileged access to a system. (CVE-2019-7221)

An information leakage issue was found in the way Linux kernel's KVM hypervisor handled page fault exceptions while emulating instructions like VMXON, VMCLEAR, VMPTRLD, and VMWRITE with memory address as an operand. It occurs if the operand is a mmio address, as the returned exception object holds uninitialized stack memory contents. A guest user/process could use this flaw to leak host's stack memory contents to a guest. (CVE-2019-7222)

The xfs_dinode_verify function in fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel can cause a NULL pointer dereference in xfs_ilock_attr_map_shared function. An attacker could trick a legitimate user or a privileged attacker could exploit this by mounting a crafted xfs filesystem image to cause a kernel panic and thus a denial of service. (CVE-2018-10322)

The Linux kernel is vulnerable to a NULL pointer dereference in the ext4/mballoc.c:ext4_process_freed_data() function. An attacker could trick a legitimate user or a privileged attacker could exploit this by mounting a crafted ext4 image to cause a kernel panic.(CVE-2018-1092)

The Lin ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.0.1.h85.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);