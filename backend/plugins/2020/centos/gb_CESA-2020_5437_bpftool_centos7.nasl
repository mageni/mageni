# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883313");
  script_version("2020-12-30T05:23:09+0000");
  script_cve_id("CVE-2019-18282", "CVE-2020-10769", "CVE-2020-14314", "CVE-2020-14385", "CVE-2020-24394", "CVE-2020-25212", "CVE-2020-25643");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2020-12-30 11:15:03 +0000 (Wed, 30 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-22 04:00:47 +0000 (Tue, 22 Dec 2020)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2020:5437)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2020:5437");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-December/048241.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2020:5437 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: metadata validator in XFS may cause an inode with a valid,
user-creatable extended attribute to be flagged as corrupt (CVE-2020-14385)

  * kernel: The flow_dissector feature allows device tracking
(CVE-2019-18282)

  * kernel: Buffer over-read in crypto_authenc_extractkeys() when a payload
longer than 4 bytes is not aligned. (CVE-2020-10769)

  * kernel: buffer uses out of index in ext3/4 filesystem (CVE-2020-14314)

  * kernel: umask not applied on filesystem without ACL support
(CVE-2020-24394)

  * kernel: TOCTOU mismatch in the NFS client code (CVE-2020-25212)

  * kernel: improper input validation in ppp_cp_parse_cr function leads to
memory corruption and read overflow (CVE-2020-25643)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * WARNING in set_restore_sigmask  at
./arch/x86/include/asm/thread_info.h:298 sigsuspend+0x6d/0x70 (BZ#1704650)

  * [i40e] VFs see other VF's outgoing traffic (BZ#1845677)

  * [Hyper-V][RHEL7] Two fixes for kdump over network (BZ#1846667)

  * Loop in __run_timers() because base->timer_jiffies is very far behind
causes a lockup condition. (BZ#1849716)

  * XFS transaction overrun when running docker on VMWARE  (overlay fs)
(BZ#1857203)

  * RHEL 7.9 NVMe/IB - Host crash encountered during array upgrade
(BZ#1857397)

  * False positive hard lockup detected while disabling the hard lockup
detector via sysctl -w kernel.watchdog=0 (BZ#1860661)

  * [Hyper-V][RHEL-7] Only notify Hyper-V for die events that are oops
(BZ#1868130)

  * Linux kernel crash due to openvswitch module (BZ#1869190)

  * 'nodfs' option not working when using SMB2+ (BZ#1873033)

  * RHEL7.7 zstream - ESS - kernel panic triggered by freelist pointer
corruption (BZ#1873189)

  * destroy_cfs_bandwidth() is called by free_fair_sched_group() without
calling init_cfs_bandwidth() (BZ#1878000)

  * NULL pointer at nvme_rdma_setup_ctrl+0x1c2/0x8d0 [nvme_rdma] when
discover E5700 (BZ#1878950)

  * IB Infiniband RDMA mlx5_ib is freeing a kmalloc-512 cache that it does
not own causing memory corruption. (BZ#1880184)

  * [Azure][RHEL7] Two Patches Needed To Enable Azure Host Time-syncing in
VMs (BZ#1884735)

  * connect AF_UNSPEC on a connecting AF_INET6 socket returns an error
(BZ#1886305)

  * Rebuilding the grub with the CPU flag 'avx' disabled (clearcpuid=156)
triggers kernel panic in xor_avx_2() (BZ#1886792)

  * nf_conntrack_sctp.h is not usable due to a missing commit (BZ#1887975)

  * Starting pvmove on top of physical volumes on MD devices causes IO error
on ongoing IO (BZ#1890059)");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1160.11.1.el7", rls:"CentOS7"))) {
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