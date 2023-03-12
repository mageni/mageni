# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0406.1");
  script_cve_id("CVE-2022-3105", "CVE-2022-3107", "CVE-2022-3108", "CVE-2022-3112", "CVE-2022-3115", "CVE-2022-3435", "CVE-2022-3564", "CVE-2022-3643", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-4662", "CVE-2022-47520", "CVE-2022-47929", "CVE-2023-0266", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"creation_date", value:"2023-02-15 04:21:53 +0000 (Wed, 15 Feb 2023)");
  script_version("2023-02-15T10:09:28+0000");
  script_tag(name:"last_modification", value:"2023-02-15 10:09:28 +0000 (Wed, 15 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 15:27:00 +0000 (Mon, 12 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0406-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0406-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230406-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0406-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 LTSS kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2023-23455: Fixed a denial of service inside atm_tc_enqueue in
 net/sched/sch_atm.c because of type confusion (non-negative numbers can
 sometimes indicate a TC_ACT_SHOT condition rather than valid
 classification results) (bsc#1207125).

CVE-2023-23454: Fixed denial or service in cbq_classify in
 net/sched/sch_cbq.c (bnc#1207036).

CVE-2023-0266: Fixed a use-after-free vulnerability inside the ALSA PCM
 package. SNDRV_CTL_IOCTL_ELEM_{READ<pipe>WRITE}32 was missing locks that
 could have been used in a use-after-free that could have resulted in a
 priviledge escalation to gain ring0 access from the system user
 (bsc#1207134).

CVE-2022-47929: Fixed NULL pointer dereference bug in the traffic
 control subsystem (bnc#1207237).

CVE-2022-47520: Fixed a out-of-bounds read when parsing a Robust
 Security Network (RSN) information element from a Netlink packet in the
 WILC1000 wireless driver (bsc#1206515).

CVE-2022-4662: Fixed incorrect access control in the USB core subsystem
 that could lead a local user to crash the system (bnc#1206664).

CVE-2022-42328, CVE-2022-42329: Fixed deadlock inside the netback driver
 that could have been triggered from a VM guest (bnc#1206114).

CVE-2022-3643: Fixed reset/abort/crash via netback from VM guest
 (bnc#1206113).

CVE-2022-3564: Fixed use-after-free in l2cap_core.c of the Bluetooth
 component (bnc#1206073).

CVE-2022-3435: Fixed a out-of-bounds read in function fib_nh_match of
 the file net/ipv4/fib_semantics.c. It is possible to initiate the attack
 remotely (bnc#1204171).

CVE-2022-3115: Fixed a null pointer dereference inside malidp_crtc_reset
 in drivers/gpu/drm/arm/malidp_crtc.c that lacked a check of the return
 value of kzalloc() (bnc#1206393).

CVE-2022-3112: Fixed a null pointer dereference in amvdec_set_canvases
 in drivers/staging/media/meson/vdec/vdec_helpers.c that lacked a check
 of the return value of kzalloc() (bnc#1206399).

CVE-2022-3108: Fixed missing check of return value of kmemdup()
 (bnc#1206389).

CVE-2022-3107: Fixed missing check of return value of kvmalloc_array()
 (bnc#1206395).

CVE-2022-3105: Fixed missing check of kmalloc_array() in uapi_finalize
 in drivers/infiniband/core/uverbs_uapi.c (bnc#1206398).

The following non-security bugs were fixed:

HID: betop: check shape of output reports (git-fixes, bsc#1207186).

HID: check empty report_list in bigben_probe() (git-fixes, bsc#1206784).

HID: check empty report_list in hid_validate_values() (git-fixes,
 bsc#1206784).

NFS: Handle missing attributes in OPEN reply (bsc#1203740).

constraints: increase disk space for all architectures (bsc#1203693).

ipv6: ping: fix wrong checksum for large frames (bsc#1203183).

mm: /proc/pid/smaps_rollup: fix no vma's null-deref (bsc#1207769).

net: sched: atm: dont intepret ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Availability 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.142.1.150200.9.67.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debuginfo", rpm:"kernel-preempt-debuginfo~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-debugsource", rpm:"kernel-preempt-debugsource~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel-debuginfo", rpm:"kernel-preempt-devel-debuginfo~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.3.18~150200.24.142.1", rls:"SLES15.0SP2"))) {
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
