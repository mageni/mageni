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
  script_oid("1.3.6.1.4.1.25623.1.0.854989");
  script_version("2022-09-21T10:12:28+0000");
  script_cve_id("CVE-2016-3695", "CVE-2020-36516", "CVE-2021-33135", "CVE-2021-4037", "CVE-2022-1184", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-2585", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-2639", "CVE-2022-2663", "CVE-2022-28356", "CVE-2022-28693", "CVE-2022-2873", "CVE-2022-2905", "CVE-2022-2938", "CVE-2022-2959", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-3078", "CVE-2022-36879", "CVE-2022-36946", "CVE-2022-39188", "CVE-2022-39190");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-21 10:12:28 +0000 (Wed, 21 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-11 17:31:00 +0000 (Fri, 11 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-09-17 01:02:19 +0000 (Sat, 17 Sep 2022)");
  script_name("openSUSE: Security Advisory for the (SUSE-SU-2022:3288-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3288-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7ANQ5K64BNLAAZMGACUGMYBV7Z2ZD5QC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the SUSE-SU-2022:3288-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 Azure kernel was updated to receive
     various security and bugfixes.
  The following security bugs were fixed:

  - CVE-2022-39190: Fixed an issue that was discovered in
       net/netfilter/nf_tables_api.c and could cause a denial of service upon
       binding to an already bound chain (bnc#1203117).

  - CVE-2022-39188: Fixed race condition in include/asm-generic/tlb.h where
       a device driver can free a page while it still has stale TLB entries
       (bnc#1203107).

  - CVE-2022-36946: Fixed a denial of service (panic) inside nfqnl_mangle in
       net/netfilter/nfnetlink_queue.c (bnc#1201940).

  - CVE-2022-36879: Fixed an issue in xfrm_expand_policies in
       net/xfrm/xfrm_policy.c where a refcount could be dropped twice
       (bnc#1201948).

  - CVE-2022-3078: Fixed a lack of check after calling vzalloc() and lack of
       free after allocation in drivers/media/test-drivers/vidtv/vidtv_s302m.c
       (bnc#1203041).

  - CVE-2022-3028: Fixed race condition that was found in the IP framework
       for transforming packets (XFRM subsystem) (bnc#1202898).

  - CVE-2022-2977: Fixed reference counting for struct tpm_chip
       (bsc#1202672).

  - CVE-2022-2959: Fixed a race condition that was found inside the watch
       queue due to a missing lock in pipe_resize_ring() (bnc#1202681).

  - CVE-2022-2938: Fixed a flaw that was found inside the Pressure Stall
       Information implementation that could have been used to allow an
       attacker to crash the system or have other memory-corruption side
       effects (bnc#1202623).

  - CVE-2022-2905: Fixed tnum_range usage on array range checking for poke
       descriptors (bsc#1202564, bsc#1202860).

  - CVE-2022-2873: Fixed an out-of-bounds memory access flaw that was found
       in iSMT SMBus host controller driver (bnc#1202558).

  - CVE-2022-28693: Fixed x86/speculation behavior by disabling RRSBA
       (bsc#1201455).

  - CVE-2022-28356: Fixed a refcount leak bug that was found in
       net/llc/af_llc.c (bnc#1197391).

  - CVE-2022-2663: Fixed an issue that was found in nf_conntrack_irc where
       the message handling could be confused and incorrectly matches the
       message (bnc#1202097).

  - CVE-2022-2639: Fixed an integer coercion error that was found in the
       openvswitch kernel module (bnc#1202154).

  - CVE-2022-26373: Fixed non-transparent sharing of return predictor
       targets between contexts in some Intel Processors that may have allowed
       information disclosure via local access (bnc#1201726).

  - CVE-2022-2588: Fixed  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure", rpm:"cluster-md-kmp-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure-debuginfo", rpm:"cluster-md-kmp-azure-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure", rpm:"dlm-kmp-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure-debuginfo", rpm:"dlm-kmp-azure-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure", rpm:"gfs2-kmp-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure-debuginfo", rpm:"gfs2-kmp-azure-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra-debuginfo", rpm:"kernel-azure-extra-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-livepatch-devel", rpm:"kernel-azure-livepatch-devel~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional", rpm:"kernel-azure-optional~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional-debuginfo", rpm:"kernel-azure-optional-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure", rpm:"kselftests-kmp-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure-debuginfo", rpm:"kselftests-kmp-azure-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure", rpm:"ocfs2-kmp-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure-debuginfo", rpm:"ocfs2-kmp-azure-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure", rpm:"reiserfs-kmp-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure-debuginfo", rpm:"reiserfs-kmp-azure-debuginfo~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150400.14.13.1", rls:"openSUSELeap15.4"))) {
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