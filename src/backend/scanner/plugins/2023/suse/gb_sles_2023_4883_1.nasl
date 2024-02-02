# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4883.1");
  script_cve_id("CVE-2023-0461", "CVE-2023-31083", "CVE-2023-39197", "CVE-2023-39198", "CVE-2023-45863", "CVE-2023-45871", "CVE-2023-5717");
  script_tag(name:"creation_date", value:"2023-12-18 04:21:02 +0000 (Mon, 18 Dec 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-04 03:24:15 +0000 (Sat, 04 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4883-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4883-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234883-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:4883-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-0461: Fixed use-after-free in icsk_ulp_data (bsc#1208787).
CVE-2023-31083: Fixed race condition in hci_uart_tty_ioctl (bsc#1210780).
CVE-2023-39197: Fixed a out-of-bounds read in nf_conntrack_dccp_packet() (bsc#1216976).
CVE-2023-39198: Fixed a race condition leading to use-after-free in qxl_mode_dumb_create() (bsc#1216965).
CVE-2023-45863: Fixed a out-of-bounds write in fill_kobj_path() (bsc#1216058).
CVE-2023-45871: Fixed an issue in the IGB driver, where the buffer size may not be adequate for frames larger than the MTU (bsc#1216259).
CVE-2023-5717: Fixed a heap out-of-bounds write vulnerability in the Performance Events component (bsc#1216584).

The following non-security bugs were fixed:

cpu/SMT: Allow enabling partial SMT states via sysfs (bsc#1214285 bsc#1205462 ltc#200161 ltc#200588).
cpu/SMT: Create topology_smt_thread_allowed() (bsc#1214285 bsc#1205462 ltc#200161 ltc#200588).
cpu/SMT: Move SMT prototypes into cpu_smt.h (bsc#1214408).
cpu/SMT: Move smt/control simple exit cases earlier (bsc#1214408).
cpu/SMT: Remove topology_smt_supported() (bsc#1214408).
cpu/SMT: Store the current/max number of threads (bsc#1214408).
cpu/hotplug: Create SMT sysfs interface for all arches (bsc#1214285 bsc#1205462 ltc#200161 ltc#200588).
dm-raid: remove useless checking in raid_message() (git-fixes).
l2tp: fix refcount leakage on PPPoL2TP sockets (git-fixes).
l2tp: fix {pppol2tp, l2tp_dfs}_seq_stop() in case of seq_file overflow (git-fixes).
md/bitmap: always wake up md_thread in timeout_store (git-fixes).
md/bitmap: factor out a helper to set timeout (git-fixes).
md/raid10: Do not add spare disk when recovery fails (git-fixes).
md/raid10: check slab-out-of-bounds in md_bitmap_get_counter (git-fixes).
md/raid10: clean up md_add_new_disk() (git-fixes).
md/raid10: fix io loss while replacement replace rdev (git-fixes).
md/raid10: fix leak of 'r10bio->remaining' for recovery (git-fixes).
md/raid10: fix memleak for 'conf->bio_split' (git-fixes).
md/raid10: fix memleak of md thread (git-fixes).
md/raid10: fix null-ptr-deref in raid10_sync_request (git-fixes).
md/raid10: fix null-ptr-deref of mreplace in raid10_sync_request (git-fixes).
md/raid10: fix overflow of md/safe_mode_delay (git-fixes).
md/raid10: fix wrong setting of max_corr_read_errors (git-fixes).
md/raid10: improve code of mrdev in raid10_sync_request (git-fixes).
md/raid10: prevent soft lockup while flush writes (git-fixes).
md/raid10: prioritize adding disk to 'removed' mirror (git-fixes).
md: Flush workqueue md_rdev_misc_wq in md_alloc() (git-fixes).
md: add new workqueue for delete rdev (git-fixes).
md: avoid signed overflow in slot_store() (git-fixes).
md: do not return existing mddevs from mddev_find_or_alloc (git-fixes).
md: factor out a mddev_alloc_unit helper from ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.160.1", rls:"SLES12.0SP5"))) {
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
