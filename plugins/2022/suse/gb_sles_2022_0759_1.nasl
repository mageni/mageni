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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0759.1");
  script_cve_id("CVE-2021-44879", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0516", "CVE-2022-0617", "CVE-2022-0644", "CVE-2022-0847", "CVE-2022-24448", "CVE-2022-24958", "CVE-2022-24959", "CVE-2022-25258", "CVE-2022-25375");
  script_tag(name:"creation_date", value:"2022-03-09 04:10:18 +0000 (Wed, 09 Mar 2022)");
  script_version("2022-03-09T08:30:28+0000");
  script_tag(name:"last_modification", value:"2022-03-09 11:12:38 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-17 19:28:00 +0000 (Thu, 17 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0759-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0759-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220759-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0759-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.


Transient execution side-channel attacks attacking the Branch History Buffer (BHB), named 'Branch Target Injection' and 'Intra-Mode Branch History Injection' are now mitigated.

The following security bugs were fixed:

CVE-2022-0001: Fixed Branch History Injection vulnerability
 (bsc#1191580).

CVE-2022-0002: Fixed Intra-Mode Branch Target Injection vulnerability
 (bsc#1191580).

CVE-2022-0847: Fixed a vulnerability were a local attackers could
 overwrite data in arbitrary (read-only) files (bsc#1196584).

CVE-2022-0617: Fixed a null pointer dereference in UDF file system
 functionality. A local user could crash the system by triggering
 udf_file_write_iter() via a malicious UDF image. (bsc#1196079)

CVE-2022-0644: Fixed a denial of service by a local user. A assertion
 failure could be triggered in kernel_read_file_from_fd() (bsc#1196155).

CVE-2021-44879: In gc_data_segment() in fs/f2fs/gc.c, special files were
 not considered, which lead to a move_data_page NULL pointer dereference
 (bsc#1195987).

CVE-2022-24959: Fixed a memory leak in yam_siocdevprivate() in
 drivers/net/hamradio/yam.c (bsc#1195897).

CVE-2022-0487: A use-after-free vulnerability was found in
 rtsx_usb_ms_drv_remove() in drivers/memstick/host/rtsx_usb_ms.c
 (bsc#1194516).

CVE-2022-0492: Fixed a privilege escalation related to cgroups v1
 release_agent feature, which allowed bypassing namespace isolation
 unexpectedly (bsc#1195543).

CVE-2022-24448: Fixed an issue in fs/nfs/dir.c. If an application sets
 the O_DIRECTORY flag, and tries to open a regular file,
 nfs_atomic_open() performs a regular lookup. If a regular file is found,
 ENOTDIR should have occurred, but the server instead returned
 uninitialized data in the file descriptor (bsc#1195612).

CVE-2022-25375: The RNDIS USB gadget lacks validation of the size of the
 RNDIS_MSG_SET command. Attackers can obtain sensitive information from
 kernel memory (bsc#1196235).

CVE-2022-0516: Fixed missing check in ioctl related to KVM in s390
 allows kernel memory read/write (bsc#1195516).

CVE-2022-25258: The USB Gadget subsystem lacked certain validation of
 interface OS descriptor requests, which could have lead to memory
 corruption (bsc#1196096).

CVE-2022-24958: drivers/usb/gadget/legacy/inode.c mishandled dev->buf
 release (bsc#1195905).

The following non-security bugs were fixed:

btrfs: check for missing device in btrfs_trim_fs (bsc#1195701).

gve: Add RX context (jsc#SLE-23652).

gve: Add a jumbo-frame device option (jsc#SLE-23652).

gve: Add consumed counts to ethtool stats (jsc#SLE-23652).

gve: Add optional metadata descriptor type GVE_TXD_MTD (jsc#SLE-23652).

gve: Correct order of processing device options (jsc#SLE-23652).

gve: Fix GFP flags when allocing pages (jsc#SLE-23652).

gve: Implement packet continuation for RX (jsc#SLE-23652).

gve: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.107.1.9.50.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.107.1", rls:"SLES15.0SP2"))) {
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
