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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0618.1");
  script_cve_id("CVE-2022-3107", "CVE-2022-3108", "CVE-2022-3564", "CVE-2022-36280", "CVE-2022-4662", "CVE-2022-47929", "CVE-2023-0045", "CVE-2023-0266", "CVE-2023-0590", "CVE-2023-23454");
  script_tag(name:"creation_date", value:"2023-03-28 13:04:06 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-29T10:10:12+0000");
  script_tag(name:"last_modification", value:"2023-03-29 10:10:12 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:00 +0000 (Mon, 06 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0618-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230618-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-23454: Fixed denial or service in cbq_classify in net/sched/sch_cbq.c (bnc#1207036).
CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
CVE-2023-0266: Fixed a use-after-free vulnerability inside the ALSA PCM package. SNDRV_CTL_IOCTL_ELEM_{READ<pipe>WRITE}32 was missing locks that could have been used in a use-after-free that could have resulted in a priviledge escalation to gain ring0 access from the system user (bsc#1207134).
CVE-2023-0045: Fixed flush IBP in ib_prctl_set() (bsc#1207773).
CVE-2022-47929: Fixed NULL pointer dereference bug in the traffic control subsystem (bnc#1207237).
CVE-2022-4662: Fixed incorrect access control in the USB core subsystem that could lead a local user to crash the system (bnc#1206664).
CVE-2022-36280: Fixed an out-of-bounds memory access vulnerability that was found in vmwgfx driver in drivers/gpu/vmxgfx/vmxgfx_kms.c (bnc#1203332).
CVE-2022-3564: Fixed use-after-free in l2cap_core.c of the Bluetooth component (bnc#1206073).
CVE-2022-3108: Fixed missing check of return value of kmemdup() (bnc#1206389).
CVE-2022-3107: Fixed missing check of return value of kvmalloc_array() (bnc#1206395).

The following non-security bugs were fixed:

Bluetooth: hci_qca: Fix the teardown problem for real (git-fixes).
CDC-NCM: remove 'connected' log message (git-fixes).
HID: betop: check shape of output reports (git-fixes, bsc#1207186).
HID: betop: fix slab-out-of-bounds Write in betop_probe (git-fixes, bsc#1207186).
HID: check empty report_list in hid_validate_values() (git-fixes, bsc#1206784).
Input: convert autorepeat timer to use timer_setup() (git-fixes).
Input: do not use WARN() in input_alloc_absinfo() (git-fixes).
Input: i8042 - Add quirk for Fujitsu Lifebook T725 (git-fixes).
Input: iforce - reformat the packet dump output (git-fixes).
Input: iforce - wake up after clearing IFORCE_XMIT_RUNNING flag (git-fixes).
Input: replace hard coded string with func in pr_err() (git-fixes).
Input: switch to using sizeof(*type) when allocating memory (git-fixes).
Input: use seq_putc() in input_seq_print_bitmap() (git-fixes).
Input: use seq_puts() in input_devices_seq_show() (git-fixes).
Makefile: link with -z noexecstack --no-warn-rwx-segments (bsc#1203200).
NFS Handle missing attributes in OPEN reply (bsc#1203740).
NFS: Correct size calculation for create reply length (git-fixes).
NFS: Fix an Oops in nfs_d_automount() (git-fixes).
NFS: Fix initialisation of I/O result struct in nfs_pgio_rpcsetup (git-fixes).
NFS: Fix memory leaks in nfs_pageio_stop_mirroring() (git-fixes).
NFS: direct.c: Fix memory leak of dreq when nfs_get_lock_context fails (git-fixes).
NFS: nfs_compare_mount_options always compare auth flavors (git-fixes).
NFS: nfs_find_open_context() may only select open files (git-fixes).
NFS: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.124.1", rls:"SLES12.0SP5"))) {
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
