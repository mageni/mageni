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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2080.1");
  script_cve_id("CVE-2019-19377", "CVE-2021-33061", "CVE-2021-39711", "CVE-2022-1184", "CVE-2022-1652", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1966", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21180", "CVE-2022-21499", "CVE-2022-24448", "CVE-2022-30594");
  script_tag(name:"creation_date", value:"2022-06-15 04:32:10 +0000 (Wed, 15 Jun 2022)");
  script_version("2022-06-15T04:32:10+0000");
  script_tag(name:"last_modification", value:"2022-06-15 10:13:29 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-10 16:36:00 +0000 (Fri, 10 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2080-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2080-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222080-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2080-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated.

The following security bugs were fixed:

CVE-2019-19377: Fixed an user-after-free that could be triggered when an
 attacker mounts a crafted btrfs filesystem image. (bnc#1158266)

CVE-2022-1975: Fixed a sleep-in-atomic bug that allows attacker to crash
 linux kernel by simulating nfc device from user-space. (bsc#1200143)

CVE-2022-21127: Fixed a stale MMIO data transient which can be exploited
 to speculatively/transiently disclose information via spectre like
 attacks. (bsc#1199650)

CVE-2022-21123: Fixed a stale MMIO data transient which can be exploited
 to speculatively/transiently disclose information via spectre like
 attacks. (bsc#1199650)

CVE-2022-21125: Fixed a stale MMIO data transient which can be exploited
 to speculatively/transiently disclose information via spectre like
 attacks. (bsc#1199650)

CVE-2022-21180: Fixed a stale MMIO data transient which can be exploited
 to speculatively/transiently disclose information via spectre like
 attacks. (bsc#1199650)

CVE-2022-21166: Fixed a stale MMIO data transient which can be exploited
 to speculatively/transiently disclose information via spectre like
 attacks. (bsc#1199650)

CVE-2022-1974: Fixed an use-after-free that could causes kernel crash by
 simulating an nfc device from user-space. (bsc#1200144)

CVE-2022-24448: Fixed an issue if an application sets the O_DIRECTORY
 flag, and tries to open a regular file, nfs_atomic_open() performs a
 regular lookup. If a regular file is found, ENOTDIR should have occurred,
 but the server instead returned uninitialized data in the file
 descriptor (bsc#1195612).

CVE-2022-1966: Fixed a use-after-free vulnerability in the Netfilter
 subsystem. This flaw allowed a local attacker with user access to cause
 a privilege escalation issue. (bnc#1200015)

CVE-2022-1729: Fixed a sys_perf_event_open() race condition against self
 (bsc#1199507).

CVE-2021-39711: In bpf_prog_test_run_skb of test_run.c, there is a
 possible out of bounds read due to Incorrect Size Value. This could lead
 to local information disclosure with System execution privileges needed.
 User interaction is not needed for exploitation (bnc#1197219).

CVE-2022-1184: Fixed an use-after-free and memory errors in ext4 when
 mounting and operating on a corrupted image. (bsc#1198577)

CVE-2022-21499: Reinforce the kernel lockdown feature, until now it's
 been trivial to break out of it with kgdb or kdb. (bsc#1199426)

CVE-2022-1652: Fixed a statically allocated error counter inside the
 floppy kernel module (bsc#1199063).

CVE-2022-1734: Fixed a r/w use-after-free when non synchronized between
 cleanup routine and firmware download routine. (bnc#1199605)

CVE-2022-30594: Fixed restriction bypass on setting the
 PT_SUSPEND_SECCOMP flag (bnc#1199505).

CVE-2021-33061: Fixed insufficient control flow management for the
 Intel(R) 82599 Ethernet Controllers and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.100.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.100.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.100.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.100.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.100.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.100.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.100.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.100.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.100.1", rls:"SLES12.0SP5"))) {
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
