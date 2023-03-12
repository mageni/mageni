# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0409.1");
  script_cve_id("CVE-2022-3606", "CVE-2023-0179");
  script_tag(name:"creation_date", value:"2023-02-15 04:21:53 +0000 (Wed, 15 Feb 2023)");
  script_version("2023-02-15T10:09:28+0000");
  script_tag(name:"last_modification", value:"2023-02-15 10:09:28 +0000 (Wed, 15 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-21 20:18:00 +0000 (Fri, 21 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0409-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0409-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230409-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0409-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 LTSS kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-3606: Fixed a null pointer dereference inside the function
 find_prog_by_sec_insn of the file tools/lib/bpf/libbpf.c of the
 component BPF (bnc#1204502).

CVE-2023-0179: Fixed incorrect arithmetics when fetching VLAN header
 bits (bsc#1207034).

The following non-security bugs were fixed:

KVM: VMX: fix crash cleanup when KVM wasn't used (bsc#1207508).

RDMA/core: Fix ib block iterator counter overflow (bsc#1207878).

bcache: fix set_at_max_writeback_rate() for multiple attached devices
 (git-fixes).

blktrace: Fix output non-blktrace event when blk_classic option enabled
 (git-fixes).

blktrace: ensure our debugfs dir exists (git-fixes).

dm btree: add a defensive bounds check to insert_at() (git-fixes).

dm cache: Fix ABBA deadlock between shrink_slab and
 dm_cache_metadata_abort (git-fixes).

dm cache: Fix UAF in destroy() (git-fixes).

dm cache: set needs_check flag after aborting metadata (git-fixes).

dm clone: Fix UAF in clone_dtr() (git-fixes).

dm integrity: Fix UAF in dm_integrity_dtr() (git-fixes).

dm integrity: fix flush with external metadata device (git-fixes).

dm integrity: flush the journal on suspend (git-fixes).

dm integrity: select CRYPTO_SKCIPHER (git-fixes).

dm ioctl: fix misbehavior if list_versions races with module loading
 (git-fixes).

dm ioctl: prevent potential spectre v1 gadget (git-fixes).

dm space map common: add bounds check to sm_ll_lookup_bitmap()
 (git-fixes).

dm space maps: do not reset space map allocation cursor when committing
 (git-fixes).

dm table: Remove BUG_ON(in_interrupt()) (git-fixes).

dm thin: Fix ABBA deadlock between shrink_slab and
 dm_pool_abort_metadata (git-fixes).

dm thin: Fix UAF in run_timer_softirq() (git-fixes).

dm thin: Use last transaction's pmd->root when commit failed (git-fixes).

dm thin: resume even if in FAIL mode (git-fixes).

dm verity: fix require_signatures module_param permissions (git-fixes).

dm verity: skip verity work if I/O error when system is shutting down
 (git-fixes).

drivers:md:fix a potential use-after-free bug (git-fixes).

kabi/severities: add mlx5 internal symbols

loop: unset GENHD_FL_NO_PART_SCAN on LOOP_CONFIGURE (git-fixes).

loop: use sysfs_emit() in the sysfs xxx show() (git-fixes).

md/raid5: Wait for MD_SB_CHANGE_PENDING in raid5d (git-fixes).

md: Flush workqueue md_rdev_misc_wq in md_alloc() (git-fixes).

md: Notify sysfs sync_completed in md_reap_sync_thread() (git-fixes).

md: protect md_unregister_thread from reentrancy (git-fixes).

mm: /proc/pid/smaps_rollup: fix no vma's null-deref (bsc#1207769).

nbd: Fix hung on disconnect request if socket is closed before
 (git-fixes).

nbd: Fix hung when signal interrupts nbd_start_device_ioctl()
 (git-fixes).

nbd: Fix incorrect error handle when first_minor is illegal in
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Availability 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Live Patching 15-SP3, SUSE Linux Enterprise Realtime Extension 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.112.1.150300.18.64.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~150300.59.112.1", rls:"SLES15.0SP3"))) {
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
