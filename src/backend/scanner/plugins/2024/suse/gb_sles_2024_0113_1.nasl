# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0113.1");
  script_cve_id("CVE-2020-26555", "CVE-2022-2586", "CVE-2023-51779", "CVE-2023-6121", "CVE-2023-6606", "CVE-2023-6610", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2024-01-18 04:20:23 +0000 (Thu, 18 Jan 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-12 16:21:26 +0000 (Fri, 12 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0113-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0113-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240113-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0113-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-6610: Fixed an out of bounds read in the SMB client when printing debug information (bsc#1217946).
CVE-2022-2586: Fixed a use-after-free which can be triggered when a nft table is deleted (bsc#1202095).
CVE-2023-51779: Fixed a use-after-free because of a bt_sock_ioctl race condition in bt_sock_recvmsg (bsc#1218559).
CVE-2020-26555: Fixed Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B that may permit an unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without knowledge of the PIN (bsc#1179610 bsc#1215237).
CVE-2023-6931: Fixed a heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component that could lead to local privilege escalation. (bsc#1218258).
CVE-2023-6606: Fixed an out of bounds read in the SMB client when receiving a malformed length from a server (bsc#1217947).
CVE-2023-6932: Fixed a use-after-free vulnerability in the Linux kernel's ipv4: igmp component that could lead to local privilege escalation (bsc#1218253).
CVE-2023-6121: Fixed an out-of-bounds read vulnerability in the NVMe-oF/TCP subsystem that could lead to information leak (bsc#1217250).

The following non-security bugs were fixed:

Fix termination state for idr_for_each_entry_ul() (bsc#1109837).
Input: powermate - fix use-after-free in powermate_config_complete (git-fixes).
KVM: s390/mm: Properly reset no-dat (git-fixes bsc#1218057).
KVM: s390: vsie: fix wrong VIR 37 when MSO is used (git-fixes bsc#1217936).
Limit kernel-source build to architectures for which the kernel binary is built (bsc#1108281).
PCI: Disable ATS for specific Intel IPU E2000 devices (bsc#1218622).
Resolve build warnings from previous series due to missing commit for Ice Lake freerunning counters perf/x86/intel/uncore: Add box_offsets for free-running counters (jsc#PED-5023 bsc#1211439).
Revert 'Limit kernel-source-azure build to architectures for which we build binaries (bsc#1108281).'
bcache: Fix __bch_btree_node_alloc to make the failure behavior consistent (git-fixes).
bcache: Remove unnecessary NULL point check in node allocations (git-fixes).
bcache: add code comments for bch_btree_node_get() and __bch_btree_node_alloc() (git-fixes).
bcache: check return value from btree_node_alloc_replacement() (git-fixes).
bcache: prevent potential division by zero error (git-fixes).
bcache: replace a mistaken IS_ERR() by IS_ERR_OR_NULL() in btree_gc_coalesce() (git-fixes).
bcache: revert replacing IS_ERR_OR_NULL with IS_ERR (git-fixes).
dm cache policy smq: ensure IO does not prevent cleaner policy progress (git-fixes).
dm cache: add cond_resched() to various workqueue loops (git-fixes).
dm crypt: add cond_resched() to dmcrypt_write() (git-fixes).
dm flakey: do not corrupt the zero ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.163.1", rls:"SLES12.0SP5"))) {
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
