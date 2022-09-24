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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3294.1");
  script_cve_id("CVE-2019-3900", "CVE-2020-36516", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-21385", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-2991", "CVE-2022-3028", "CVE-2022-36879", "CVE-2022-39188");
  script_tag(name:"creation_date", value:"2022-09-19 05:10:56 +0000 (Mon, 19 Sep 2022)");
  script_version("2022-09-19T10:11:35+0000");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-06 18:09:00 +0000 (Tue, 06 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3294-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3294-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223294-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3294-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated receive various security and bugfixes.

The following security bugs were fixed:

CVE-2022-39188: Fixed race condition in include/asm-generic/tlb.h where
 a device driver can free a page while it still has stale TLB entries
 (bnc#1203107).

CVE-2022-36879: Fixed an issue in xfrm_expand_policies in
 net/xfrm/xfrm_policy.c where a refcount could be dropped twice
 (bnc#1201948).

CVE-2022-3028: Fixed race condition that was found in the IP framework
 for transforming packets (XFRM subsystem) (bnc#1202898).

CVE-2022-2991: Fixed an heap-based overflow in the lightnvm
 implemenation (bsc#1201420).

CVE-2022-26373: Fixed non-transparent sharing of return predictor
 targets between contexts in some Intel Processors (bnc#1201726).

CVE-2022-2588: Fixed use-after-free in cls_route (bsc#1202096).

CVE-2022-21385: Fixed a flaw in net_rds_alloc_sgs() that allowed
 unprivileged local users to crash the machine (bnc#1202897).

CVE-2022-20369: Fixed out of bounds write in v4l2_m2m_querybuf of
 v4l2-mem2mem.c (bnc#1202347).

CVE-2022-20368: Fixed slab-out-of-bounds access in packet_recvmsg()
 (bsc#1202346).

CVE-2020-36516: Fixed an issue in the mixed IPID assignment method where
 an attacker was able to inject data into or terminate a victim's TCP
 session (bnc#1196616).

CVE-2019-3900: Fixed infinite loop the vhost_net kernel module that
 could result in a DoS scenario (bnc#1133374).

The following non-security bugs were fixed:

net_sched: cls_route: Disallowed handle of 0 (bsc#1202393).

mm, rmap: Fixed anon_vma->degree ambiguity leading to double-reuse
 (bsc#1203098).

lightnvm: Removed lightnvm implemenation (bsc#1191881).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.188.1", rls:"SLES12.0SP2"))) {
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
