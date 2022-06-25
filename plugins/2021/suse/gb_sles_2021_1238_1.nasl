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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1238.1");
  script_cve_id("CVE-2019-18814", "CVE-2019-19769", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-27170", "CVE-2020-27171", "CVE-2020-27815", "CVE-2020-35519", "CVE-2020-36310", "CVE-2020-36311", "CVE-2020-36312", "CVE-2020-36322", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28038", "CVE-2021-28375", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28950", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29154", "CVE-2021-29264", "CVE-2021-29265", "CVE-2021-29647", "CVE-2021-30002", "CVE-2021-3428", "CVE-2021-3444", "CVE-2021-3483");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:40 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:30:01+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 19:15:00 +0000 (Wed, 12 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1238-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1238-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211238-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1238-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-3444: Fixed an issue with the bpf verifier which did not
 properly handle mod32 destination register truncation when the source
 register was known to be 0 leading to out of bounds read (bsc#1184170).

CVE-2021-3428: Fixed an integer overflow in ext4_es_cache_extent
 (bsc#1173485).

CVE-2021-29647: Fixed an issue in qrtr_recvmsg which could have allowed
 attackers to obtain sensitive information from kernel memory because of
 a partially uninitialized data structure (bsc#1184192 ).

CVE-2021-29265: Fixed an issue in usbip_sockfd_store which could have
 allowed attackers to cause a denial of service due to race conditions
 during an update of the local and shared status (bsc#1184167).

CVE-2021-29264: Fixed an issue in the Freescale Gianfar Ethernet driver
 which could have allowed attackers to cause a system crash due to a
 calculation of negative fragment size (bsc#1184168).

CVE-2021-28972: Fixed a user-tolerable buffer overflow when writing a
 new device name to the driver from userspace, allowing userspace to
 write data to the kernel stack frame directly (bsc#1184198).

CVE-2021-28971: Fixed an issue in intel_pmu_drain_pebs_nhm which could
 have caused a system crash because the PEBS status in a PEBS record was
 mishandled (bsc#1184196 ).

CVE-2021-28964: Fixed a race condition in get_old_root which could have
 allowed attackers to cause a denial of service (bsc#1184193).

CVE-2021-28688: Fixed an issue introduced by XSA-365 (bsc#1183646).

CVE-2021-28660: Fixed an out of bounds write in rtw_wx_set_scan
 (bsc#1183593 ).

CVE-2021-28375: Fixed an issue in fastrpc_internal_invoke which did not
 prevent user applications from sending kernel RPC messages (bsc#1183596).

CVE-2021-28038: Fixed an issue with the netback driver which was lacking
 necessary treatment of errors such as failed memory allocations
 (bsc#1183022).

CVE-2021-27365: Fixed an issue where an unprivileged user can send a
 Netlink message that is associated with iSCSI, and has a length up to
 the maximum length of a Netlink message (bsc#1182715).

CVE-2021-27364: Fixed an issue where an attacker could craft Netlink
 messages (bsc#1182717).

CVE-2021-27363: Fixed a kernel pointer leak which could have been used
 to determine the address of the iscsi_transport structure (bsc#1182716).

CVE-2020-35519: Fixed an out-of-bounds memory access was found in
 x25_bind (bsc#1183696).

CVE-2020-27815: Fixed an issue in JFS filesystem where could have
 allowed an attacker to execute code (bsc#1179454).

CVE-2020-27171: Fixed an off-by-one error affecting out-of-bounds
 speculation on pointer arithmetic, leading to side-channel attacks that
 defeat Spectre mitigations and obtain sensitive information from kernel
 memory (bsc#1183775).

CVE-2020-27170: Fixed potential side-cha... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE MicroOS 5.0, SUSE Linux Enterprise Workstation Extension 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise High Availability 15-SP2");

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
  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.61.1.9.26.4", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.61.1", rls:"SLES15.0SP2"))){
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
