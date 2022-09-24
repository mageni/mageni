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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3293.1");
  script_cve_id("CVE-2016-3695", "CVE-2020-36516", "CVE-2021-33135", "CVE-2021-4037", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-2588", "CVE-2022-2639", "CVE-2022-2663", "CVE-2022-28356", "CVE-2022-28693", "CVE-2022-2873", "CVE-2022-2905", "CVE-2022-2938", "CVE-2022-2959", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-3078", "CVE-2022-32250", "CVE-2022-36879", "CVE-2022-36946", "CVE-2022-39188", "CVE-2022-39190");
  script_tag(name:"creation_date", value:"2022-09-19 05:10:56 +0000 (Mon, 19 Sep 2022)");
  script_version("2022-09-19T10:11:35+0000");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-12 02:27:00 +0000 (Sun, 12 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3293-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223293-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-39190: Fixed an issue that was discovered in
 net/netfilter/nf_tables_api.c and could cause a denial of service upon
 binding to an already bound chain (bnc#1203117).

CVE-2022-39188: Fixed race condition in include/asm-generic/tlb.h where
 a device driver can free a page while it still has stale TLB entries
 (bnc#1203107).

CVE-2022-2663: Fixed an issue that was found in nf_conntrack_irc where
 the message handling could be confused and incorrectly matches the
 message (bnc#1202097).

CVE-2022-3078: Fixed a lack of check after calling vzalloc() and lack of
 free after allocation in drivers/media/test-drivers/vidtv/vidtv_s302m.c
 (bnc#1203041).

CVE-2022-28356: Fixed a refcount leak bug that was found in
 net/llc/af_llc.c (bnc#1197391).

CVE-2022-3028: Fixed race condition that was found in the IP framework
 for transforming packets (XFRM subsystem) (bnc#1202898).

CVE-2022-2905: Fixed tnum_range usage on array range checking for poke
 descriptors (bsc#1202564, bsc#1202860).

CVE-2022-2977: Fixed reference counting for struct tpm_chip
 (bsc#1202672).

CVE-2022-2938: Fixed a flaw that was found inside the Pressure Stall
 Information implementation that could have been used to allow an
 attacker to crash the system or have other memory-corruption side
 effects (bnc#1202623).

CVE-2022-28693: Fixed x86/speculation behavior by disabling RRSBA
 (bsc#1201455).

CVE-2021-33135: Fixed uncontrolled resource consumption inside Intel(R)
 SGX that may have allowed an authenticated user to potentially enable
 denial of service via local access (bnc#1199515).

CVE-2022-2588: Fixed use-after-free in cls_route (bsc#1202096).

CVE-2022-2959: Fixed a race condition that was found inside the watch
 queue due to a missing lock in pipe_resize_ring() (bnc#1202681
 bnc#1202685).

CVE-2022-36946: Fixed a denial of service (panic) inside nfqnl_mangle in
 net/netfilter/nfnetlink_queue.c (bnc#1201940 bnc#1201941 bnc#1202312
 bnc#1202874).

CVE-2021-4037: Fixed function logic vulnerability that allowed local
 users to create files for the XFS file-system with an unintended group
 ownership and with group execution and SGID permission bits set
 (bnc#1198702).

CVE-2022-2873: Fixed an out-of-bounds memory access flaw that was found
 in iSMT SMBus host controller driver (bnc#1202558).

CVE-2022-36879: Fixed an issue in xfrm_expand_policies in
 net/xfrm/xfrm_policy.c where a refcount could be dropped twice
 (bnc#1201948).

CVE-2022-20368: Fixed slab-out-of-bounds access in packet_recvmsg()
 (bsc#1202346).

CVE-2022-20369: Fixed out of bounds write in v4l2_m2m_querybuf of
 v4l2-mem2mem.c (bnc#1202347).

CVE-2016-3695: Fixed an issue inside the einj_error_inject function in
 drivers/acpi/apei/einj.c that allowed users to simulate hardware errors
 and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP4, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Module for Legacy Software 15-SP4, SUSE Linux Enterprise Module for Live Patching 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.21.2.150400.24.7.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.21.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.14.21~150400.24.21.2", rls:"SLES15.0SP4"))) {
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
