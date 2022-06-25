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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0365.1");
  script_cve_id("CVE-2021-22600", "CVE-2021-39648", "CVE-2021-39657", "CVE-2021-45095", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-22942");
  script_tag(name:"creation_date", value:"2022-02-11 03:25:31 +0000 (Fri, 11 Feb 2022)");
  script_version("2022-02-11T10:30:56+0000");
  script_tag(name:"last_modification", value:"2022-02-11 11:02:08 +0000 (Fri, 11 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-04 20:53:00 +0000 (Fri, 04 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0365-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0365-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220365-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0365-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 LTSS kernel was updated receive various security and bugfixes.

The following security bugs were fixed:

CVE-2022-0435: Fixed remote stack overflow in net/tipc module that
 validate domain record count on input (bsc#1195254).

CVE-2021-45095: Fixed refcount leak in pep_sock_accept in
 net/phonet/pep.c (bnc#1193867).

CVE-2022-22942: Fixed stale file descriptors on failed usercopy
 (bsc#1195065).

CVE-2021-22600: Fixed double free bug in packet_set_ring() in
 net/packet/af_packet.c that could have been exploited by a local user
 through crafted syscalls to escalate privileges or deny service
 (bnc#1195184).

CVE-2021-39657: Fixed out of bounds read due to a missing bounds check
 in ufshcd_eh_device_reset_handler of ufshcd.c. This could lead to local
 information disclosure with System execution privileges needed
 (bnc#1193864).

CVE-2021-39648: Fixed possible disclosure of kernel heap memory due to a
 race condition in gadget_dev_desc_UDC_show of configfs.c. This could
 lead to local information disclosure with System execution privileges
 needed. User interaction is not needed for exploitation (bnc#1193861).

CVE-2022-0330: Fixed flush TLBs before releasing backing store
 (bsc#1194880).

The following non-security bugs were fixed:

bpf: Verifer, adjust_scalar_min_max_vals to always call
 update_reg_bounds() (bsc#1194227).

btrfs: tree-checker: Add EXTENT_ITEM and METADATA_ITEM check
 (bsc#1195009).

btrfs: tree-checker: annotate all error branches as unlikely
 (bsc#1195009).

btrfs: tree-checker: check for BTRFS_BLOCK_FLAG_FULL_BACKREF being set
 improperly (bsc#1195009).

hv_netvsc: Set needed_headroom according to VF (bsc#1193506).

net, xdp: Introduce xdp_init_buff utility routine (bsc#1193506).

net, xdp: Introduce xdp_prepare_buff utility routine (bsc#1193506).

net: allow retransmitting a TCP packet if original is still in queue
 (bsc#1188605 bsc#1187428).

net: mana: Add RX fencing (bsc#1193506).

net: mana: Add XDP support (bsc#1193506).

net: sch_generic: avoid concurrent reset and enqueue op for lockless
 qdisc (bsc#1183405).

net: sched: add barrier to ensure correct ordering for lockless qdisc
 (bsc#1183405).

net: sched: avoid unnecessary seqcount operation for lockless qdisc
 (bsc#1183405).

net: sched: fix packet stuck problem for lockless qdisc (bsc#1183405).

net: sched: fix tx action reschedule issue with stopped queue
 (bsc#1183405).

net: sched: fix tx action rescheduling issue during deactivation
 (bsc#1183405).

net: sched: replaced invalid qdisc tree flush helper in qdisc_replace
 (bsc#1183405).

net_sched: avoid resetting active qdisc for multiple times (bsc#1183405).

net_sched: get rid of unnecessary dev_qdisc_reset() (bsc#1183405).

net_sched: use qdisc_reset() in qdisc_destroy() (bsc#1183405).

nvme: add 'iopolicy' module parameter (bsc#1177599 bsc#1193096).

xfrm: fix MTU regression (bsc#1185377, bsc#1194048).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Availability 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Micro 5.0, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Realtime Extension 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.102.1.9.48.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.102.1", rls:"SLES15.0SP2"))) {
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
