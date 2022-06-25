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
  script_oid("1.3.6.1.4.1.25623.1.0.883045");
  script_version("2019-05-03T11:15:46+0000");
  script_cve_id("CVE-2019-6974", "CVE-2019-7221");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 11:15:46 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-01 02:00:59 +0000 (Wed, 01 May 2019)");
  script_name("CentOS Update for bpftool CESA-2019:0818 centos7 ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-April/023278.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2019:0818 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * Kernel: KVM: potential use-after-free via kvm_ioctl_create_device()
(CVE-2019-6974)

  * Kernel: KVM: nVMX: use-after-free of the hrtimer for emulation of the
preemption timer (CVE-2019-7221)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * rbd: avoid corruption on partially completed bios [rhel-7.6.z]
(BZ#1672514)

  * xfs_vm_writepages deadly embrace between kworker and user task.
[rhel-7.6.z] (BZ#1673281)

  * Offload Connections always get vlan priority 0 [rhel-7.6.z] (BZ#1673821)

  * [NOKIA] RHEL sends flood of Neighbour Solicitations under specific
conditions [rhel-7.6.z] (BZ#1677179)

  * RHEL 7.6 - Host crash occurred on NVMe/IB system while running controller
reset [rhel-7.6.z] (BZ#1678214)

  * [rhel7] raid0 md workqueue deadlock with stacked md devices [rhel-7.6.z]
(BZ#1678215)

  * [PureStorage7.6]nvme disconnect following an unsuccessful Admin queue
creation causes kernel panic [rhel-7.6.z] (BZ#1678216)

  * RFC: Regression with -fstack-check in 'backport upstream large stack
guard patch to RHEL6' patch [rhel-7.6.z] (BZ#1678221)

  * [Hyper-V] [RHEL 7.6]hv_netvsc: Fix a network regression after ifdown/ifup
[rhel-7.6.z] (BZ#1679997)

  * rtc_cmos: probe of 00:01 failed with error -16 [rhel-7.6.z] (BZ#1683078)

  * ACPI WDAT watchdog update [rhel-7.6.z] (BZ#1683079)

  * high ovs-vswitchd CPU usage when VRRP over VXLAN tunnel causing qrouter
fail-over [rhel-7.6.z] (BZ#1683093)

  * Openshift node drops outgoing POD traffic due to NAT hashtable race in
__ip_conntrack_confirm() [rhel-7.6.z] (BZ#1686766)

  * [Backport] [v3, 2/2] net: igmp: Allow user-space configuration of igmp
unsolicited report interval [rhel-7.6.z] (BZ#1686771)

  * [RHEL7.6]: Intermittently seen FIFO parity error on T6225-SO adapter
[rhel-7.6.z] (BZ#1687487)

  * The number of unsolict report about IGMP is incorrect [rhel-7.6.z]
(BZ#1688225)

  * RDT driver causing failure to boot on AMD Rome system with more than 255
CPUs [rhel-7.6.z] (BZ#1689120)

  * mpt3sas_cm0: fault_state(0x2100)! [rhel-7.6.z] (BZ#1689379)

  * rwsem in inconsistent state leading system to hung [rhel-7.6.z]
(BZ#1690323)

Users of kernel are advised to upgrade to these updated packages, which fix
these bugs.");

  script_tag(name:"affected", value:"'bpftool' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~957.12.1.el7", rls:"CentOS7"))) {
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
