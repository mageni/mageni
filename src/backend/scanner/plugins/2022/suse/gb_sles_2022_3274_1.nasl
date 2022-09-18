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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3274.1");
  script_cve_id("CVE-2020-36516", "CVE-2020-36557", "CVE-2020-36558", "CVE-2021-4203", "CVE-2022-20166", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-21385", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-2639", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-36879", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-09-15 04:54:24 +0000 (Thu, 15 Sep 2022)");
  script_version("2022-09-15T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:06 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 19:42:00 +0000 (Wed, 07 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3274-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3274-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223274-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3274-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 LTSS kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-36946: Fixed a denial of service (panic) inside nfqnl_mangle in
 net/netfilter/nfnetlink_queue.c (bnc#1201940).

CVE-2022-36879: Fixed an issue in xfrm_expand_policies in
 net/xfrm/xfrm_policy.c where a refcount could be dropped twice
 (bnc#1201948).

CVE-2022-3028: Fixed race condition that was found in the IP framework
 for transforming packets (XFRM subsystem) (bnc#1202898).

CVE-2022-2977: Fixed reference counting for struct tpm_chip
 (bsc#1202672).

CVE-2022-2639: Fixed an integer coercion error that was found in the
 openvswitch kernel module (bnc#1202154).

CVE-2022-26373: Fixed non-transparent sharing of return predictor
 targets between contexts in some Intel Processors (bnc#1201726).

CVE-2022-2588: Fixed use-after-free in cls_route (bsc#1202096).

CVE-2022-21385: Fixed a flaw in net_rds_alloc_sgs() that allowed
 unprivileged local users to crash the machine (bnc#1202897).

CVE-2022-20369: Fixed out of bounds write in v4l2_m2m_querybuf of
 v4l2-mem2mem.c (bnc#1202347).

CVE-2022-20368: Fixed slab-out-of-bounds access in packet_recvmsg()
 (bsc#1202346).

CVE-2022-20166: Fixed possible out of bounds write due to a heap buffer
 overflow in various methods of kernel base drivers (bnc#1200598).

CVE-2021-4203: Fixed use-after-free read flaw that was found in
 sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
 SO_PEERGROUPS race with listen() (bnc#1194535).

CVE-2020-36558: Fixed a race condition involving VT_RESIZEX could lead
 to a NULL pointer dereference and general protection fault (bnc#1200910).

CVE-2020-36557: Fixed a race condition between the VT_DISALLOCATE ioctl
 and closing/opening of ttys that could have led to a use-after-free
 (bnc#1201429).

CVE-2020-36516: Fixed an issue in the mixed IPID assignment method where
 an attacker was able to inject data into or terminate a victim's TCP
 session (bnc#1196616).

The following non-security bugs were fixed:

cifs: fix error paths in cifs_tree_connect() (bsc#1177440).

cifs: fix uninitialized pointer in error case in dfs_cache_get_tgt_share
 (bsc#1188944).

cifs: report error instead of invalid when revalidating a dentry fails
 (bsc#1177440).

cifs: skip trailing separators of prefix paths (bsc#1188944).

kernel-obs-build: include qemu_fw_cfg (boo#1201705)

lightnvm: Remove lightnvm implemenation (bsc#1191881 bsc#1201420
 ZDI-CAN-17325).

mm/rmap.c: do not reuse anon_vma if we just want a copy (git-fixes,
 bsc#1203098).

mm/rmap: Fix anon_vma->degree ambiguity leading to double-reuse
 (git-fixes, bsc#1203098).

net_sched: cls_route: disallow handle of 0 (bsc#1202393).

objtool: Add --backtrace support (bsc#1202396).

objtool: Add support for intra-function calls (bsc#1202396).

objtool: Allow no-op CFI ops in alternatives (bsc#1202396).

objtool: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.108.1", rls:"SLES12.0SP4"))) {
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
