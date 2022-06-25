# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2321.1");
  script_cve_id("CVE-2019-25045", "CVE-2020-24588", "CVE-2020-26558", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-33624", "CVE-2021-34693");
  script_tag(name:"creation_date", value:"2021-07-15 09:14:13 +0000 (Thu, 15 Jul 2021)");
  script_version("2021-07-15T09:14:13+0000");
  script_tag(name:"last_modification", value:"2021-07-15 09:14:13 +0000 (Thu, 15 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-15 13:49:00 +0000 (Tue, 15 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2321-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2321-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212321-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2321-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-33624: Fixed a bug which allows unprivileged BPF program to
 leak the contents of arbitrary kernel memory (and therefore, of all
 physical memory) via a side-channel. (bsc#1187554)

CVE-2019-25045: Fixed an use-after-free issue in the Linux kernel The
 XFRM subsystem, related to an xfrm_state_fini panic. (bsc#1187049)

CVE-2021-0605: Fixed an out-of-bounds read which could lead to local
 information disclosure in the kernel with System execution privileges
 needed. (bsc#1187601)

CVE-2021-0512: Fixed a possible out-of-bounds write which could lead to
 local escalation of privilege with no additional execution privileges
 needed. (bsc#1187595)

CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure
 pairing that could permit a nearby man-in-the-middle attacker to
 identify the Passkey used during pairing. (bsc#1179610)

CVE-2021-34693: Fixed a bug in net/can/bcm.c which could allow local
 users to obtain sensitive information from kernel stack memory because
 parts of a data structure are uninitialized. (bsc#1187452)

CVE-2021-0129: Fixed an improper access control in BlueZ that may have
 allowed an authenticated user to potentially enable information
 disclosure via adjacent access. (bsc#1186463)

CVE-2020-36386: Fixed an out-of-bounds read in
 hci_extended_inquiry_result_evt. (bsc#1187038)

CVE-2020-24588: Fixed a bug that could allow an adversary to abuse
 devices that support receiving non-SSP A-MSDU frames to inject arbitrary
 network packets. (bsc#1185861)

The following non-security bugs were fixed:

ALSA: timer: Fix master timer notification (git-fixes).

alx: Fix an error handling path in 'alx_probe()' (git-fixes).

ASoC: sti-sas: add missing MODULE_DEVICE_TABLE (git-fixes).

batman-adv: Avoid WARN_ON timing related checks (git-fixes).

blk-mq: Swap two calls in blk_mq_exit_queue() (bsc#1187453).

blk-wbt: Fix missed wakeup (bsc#1186627).

block: Discard page cache of zone reset target range (bsc#1187402).

Bluetooth: fix the erroneous flush_work() order (git-fixes).

Bluetooth: use correct lock to prevent UAF of hdev object (git-fixes).

btrfs: account for new extents being deleted in total_bytes_pinned
 (bsc#1135481).

btrfs: add a comment explaining the data flush steps (bsc#1135481).

btrfs: add btrfs_reserve_data_bytes and use it (bsc#1135481).

btrfs: add flushing states for handling data reservations (bsc#1135481).

btrfs: add missing error handling after doing leaf/node binary search
 (bsc#1187833).

btrfs: add the data transaction commit logic into may_commit_transaction
 (bsc#1135481).

btrfs: call btrfs_try_granting_tickets when freeing reserved bytes
 (bsc#1135481).

btrfs: call btrfs_try_granting_tickets when reserving space
 (bsc#1135481).

btrfs: call btrfs_try_granting_tickets when unpinning... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5");

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
  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.62.1", rls:"SLES12.0SP5"))){
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
