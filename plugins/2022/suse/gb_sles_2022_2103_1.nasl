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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2103.1");
  script_cve_id("CVE-2017-13695", "CVE-2019-19377", "CVE-2019-20811", "CVE-2021-20292", "CVE-2021-20321", "CVE-2021-33061", "CVE-2021-38208", "CVE-2021-39711", "CVE-2021-43389", "CVE-2022-1011", "CVE-2022-1184", "CVE-2022-1353", "CVE-2022-1419", "CVE-2022-1516", "CVE-2022-1652", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21180", "CVE-2022-21499", "CVE-2022-30594");
  script_tag(name:"creation_date", value:"2022-06-17 04:28:40 +0000 (Fri, 17 Jun 2022)");
  script_version("2022-06-17T04:28:40+0000");
  script_tag(name:"last_modification", value:"2022-06-17 09:50:23 +0000 (Fri, 17 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-10 16:36:00 +0000 (Fri, 10 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2103-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222103-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated.

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

CVE-2019-19377: Fixed an user-after-free that could be triggered when an
 attacker mounts a crafted btrfs filesystem image. (bnc#1158266)

CVE-2022-1184: Fixed an use-after-free and memory errors in ext4 when
 mounting and operating on a corrupted image. (bsc#1198577)

CVE-2017-13695: Fixed a bug that caused a stack dump allowing local
 users to obtain sensitive information from kernel memory and bypass the
 KASLR protection mechanism via a crafted ACPI table. (bnc#1055710)

CVE-2022-1729: Fixed a sys_perf_event_open() race condition against self
 (bsc#1199507).

CVE-2022-1652: Fixed a statically allocated error counter inside the
 floppy kernel module (bsc#1199063).

CVE-2021-39711: In bpf_prog_test_run_skb of test_run.c, there is a
 possible out of bounds read due to Incorrect Size Value. This could lead
 to local information disclosure with System execution privileges needed.
 User interaction is not needed for exploitation (bnc#1197219).

CVE-2022-1419: Fixed a concurrency use-after-free in
 vgem_gem_dumb_create (bsc#1198742).

CVE-2021-43389: Fixed an array-index-out-of-bounds flaw in the
 detach_capi_ctr function in drivers/isdn/capi/kcapi.c. (bnc#1191958)

CVE-2021-38208: Fixed a denial of service (NULL pointer dereference and
 BUG) by making a getsockname call after a certain type of failure of a
 bind call (bnc#1187055).

CVE-2022-1353: Fixed access control to kernel memory in the
 pfkey_register function in net/key/af_key.c. (bnc#1198516)

CVE-2021-20292: Fixed object validation prior to performing operations
 on the object in nouveau_sgdma_create_ttm in Nouveau DRM subsystem
 (bnc#1183723).

CVE-2022-1011: Fixed an use-after-free vulnerability which could allow a
 local attacker to retireve (partial) /etc/shadow hashes or any other
 data from filesystem when he can mount a FUSE filesystems. (bnc#1197343)

CVE-2022-1974: Fixed an use-after-free that could causes kernel crash by
 simulating an nfc device from user-space. (bsc#1200144)

CVE-2022-1975: Fixed a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~150000.150.92.2", rls:"SLES15.0"))) {
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
