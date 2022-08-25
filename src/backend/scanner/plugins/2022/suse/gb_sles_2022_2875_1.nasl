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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2875.1");
  script_cve_id("CVE-2020-36516", "CVE-2020-36557", "CVE-2020-36558", "CVE-2021-33655", "CVE-2021-33656", "CVE-2022-1116", "CVE-2022-1462", "CVE-2022-20166", "CVE-2022-21505", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-2639", "CVE-2022-29581", "CVE-2022-32250", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-08-24 07:59:30 +0000 (Wed, 24 Aug 2022)");
  script_version("2022-08-24T07:59:30+0000");
  script_tag(name:"last_modification", value:"2022-08-24 07:59:30 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-12 02:27:00 +0000 (Sun, 12 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2875-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2875-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222875-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2875-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-36516: Fixed TCP session data injection vulnerability via the
 mixed IPID assignment method (bnc#1196616).

CVE-2020-36557: Fixed race condition between the VT_DISALLOCATE ioctl
 and closing/opening of ttys that could lead to a use-after-free
 (bnc#1201429).

CVE-2020-36558: Fixed race condition involving VT_RESIZEX that could
 lead to a NULL pointer dereference and general protection fault
 (bnc#1200910).

CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO
 (bnc#1201635).

CVE-2021-33656: Fixed out of bounds write with ioctl PIO_FONT
 (bnc#1201636).

CVE-2022-1116: Fixed a integer overflow vulnerability in io_uring which
 allowed a local attacker to cause memory corruption and escalate
 privileges to root (bnc#1199647).

CVE-2022-1462: Fixed an out-of-bounds read flaw in the TeleTYpe
 subsystem (bnc#1198829).

CVE-2022-2318: Fixed a use-after-free vulnerability in the timer
 handler in net/rose/rose_timer.c that allow attackers to crash the
 system without any privileges (bsc#1201251).

CVE-2022-2639: Fixed integer underflow that could lead to out-of-bounds
 write in reserve_sfa_size() (bsc#1202154).

CVE-2022-20166: Fixed possible out of bounds write due to sprintf
 unsafety that could cause local escalation of privilege (bnc#1200598)

CVE-2022-21505: Fixed kexec lockdown bypass with IMA policy
 (bsc#1201458).

CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742: Fixed
 multiple potential data leaks with Block and Network devices when using
 untrusted backends (bsc#1200762).

CVE-2022-29581: Fixed improper update of Reference Count in net/sched
 that could cause root privilege escalation (bnc#1199665).

CVE-2022-32250: Fixed user-after-free in net/netfilter/nf_tables_api.c
 that could allow local privilege escalation (bnc#1200015).

CVE-2022-36946: Fixed incorrect packet truncation in nfqnl_mangle() that
 could lead to remote DoS (bnc#1201940).

The following non-security bugs were fixed:

ACPI: APEI: Better fix to avoid spamming the console with old error logs
 (git-fixes).

ACPI: CPPC: Do not prevent CPPC from working in the future (git-fixes).

ACPI: video: Shortening quirk list by identifying Clevo by board_name
 only (git-fixes).

ALSA: hda - Add fixup for Dell Latitidue E5430 (git-fixes).

ALSA: hda/conexant: Apply quirk for another HP ProDesk 600 G3 model
 (git-fixes).

ALSA: hda/realtek - Enable the headset-mic on a Xiaomi's laptop
 (git-fixes).

ALSA: hda/realtek - Fix headset mic problem for a HP machine with alc221
 (git-fixes).

ALSA: hda/realtek - Fix headset mic problem for a HP machine with alc671
 (git-fixes).

ASoC: Intel: Skylake: Correct the handling of fmt_config flexible array
 (git-fixes).

ASoC: Intel: Skylake: Correct the ssp rate discovery in
 skl_get_ssp_clks() ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for Legacy Software 15-SP3, SUSE Linux Enterprise Module for Live Patching 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.90.1.150300.18.52.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~150300.59.90.1", rls:"SLES15.0SP3"))) {
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
