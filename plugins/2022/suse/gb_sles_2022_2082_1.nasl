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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2082.1");
  script_cve_id("CVE-2017-13695", "CVE-2018-20784", "CVE-2018-7755", "CVE-2019-19377", "CVE-2020-10769", "CVE-2021-20292", "CVE-2021-20321", "CVE-2021-28688", "CVE-2021-33061", "CVE-2021-38208", "CVE-2022-1011", "CVE-2022-1184", "CVE-2022-1353", "CVE-2022-1419", "CVE-2022-1516", "CVE-2022-1652", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21180", "CVE-2022-21499", "CVE-2022-28388", "CVE-2022-28390", "CVE-2022-30594");
  script_tag(name:"creation_date", value:"2022-06-15 04:32:10 +0000 (Wed, 15 Jun 2022)");
  script_version("2022-06-15T04:32:10+0000");
  script_tag(name:"last_modification", value:"2022-06-15 10:13:29 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:28:00 +0000 (Wed, 02 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2082-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2082-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222082-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2082-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 3.12.31 to receive various security and bugfixes.

The following security bugs were fixed:

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

CVE-2022-1975: Fixed a bug that allows an attacker to crash the linux
 kernel by simulating nfc device from user-space. (bsc#1200143)

CVE-2022-1974: Fixed an use-after-free that could causes kernel crash by
 simulating an nfc device from user-space. (bsc#1200144)

CVE-2019-19377: Fixed an user-after-free that could be triggered when an
 attacker mounts a crafted btrfs filesystem image. (bnc#1158266)

CVE-2022-1729: Fixed a sys_perf_event_open() race condition against self
 (bsc#1199507).

CVE-2022-1184: Fixed an use-after-free and memory errors in ext4 when
 mounting and operating on a corrupted image. (bsc#1198577)

CVE-2022-21499: Reinforce the kernel lockdown feature, until now it's
 been trivial to break out of it with kgdb or kdb. (bsc#1199426)

CVE-2017-13695: Fixed a bug that caused a stack dump allowing local
 users to obtain sensitive information from kernel memory and bypass the
 KASLR protection mechanism via a crafted ACPI table. (bnc#1055710)

CVE-2022-1652: Fixed a statically allocated error counter inside the
 floppy kernel module (bsc#1199063).

CVE-2022-1734: Fixed a r/w use-after-free when non synchronized between
 cleanup routine and firmware download routine. (bnc#1199605)

CVE-2022-30594: Fixed restriction bypass on setting the
 PT_SUSPEND_SECCOMP flag (bnc#1199505).

CVE-2021-28688: Fixed XSA-365 that includes initialization of pointers
 such that subsequent cleanup code wouldn't use uninitialized or stale
 values. This initialization went too far and may under certain
 conditions also overwrite pointers which are in need of cleaning up. The
 lack of cleanup would result in leaking persistent grants. The leak in
 turn would prevent fully cleaning up after a respective guest has died,
 leaving around zombie domains (bnc#1183646).

CVE-2020-10769: Fixed a buffer over-read flaw in the IPsec Cryptographic
 algorithm's module. This flaw allowed a local attacker with user
 privileges to cause a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.180~94.164.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.180~94.164.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.180~94.164.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.180~94.164.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.180~94.164.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.180~94.164.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-kgraft", rpm:"kernel-default-kgraft~4.4.180~94.164.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.180~94.164.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.180~94.164.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.180~94.164.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.180~94.164.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.180~94.164.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_164-default", rpm:"kgraft-patch-4_4_180-94_164-default~1~4.3.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_164-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_164-default-debuginfo~1~4.3.2", rls:"SLES12.0SP3"))) {
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
