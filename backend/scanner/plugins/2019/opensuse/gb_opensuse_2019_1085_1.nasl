# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852361");
  script_version("2019-04-26T08:24:31+0000");
  script_cve_id("CVE-2019-2024", "CVE-2019-9213");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-04-26 08:24:31 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-03 06:41:30 +0000 (Wed, 03 Apr 2019)");
  script_name("openSUSE Update for the openSUSE-SU-2019:1085-1 (the)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-03/msg00045.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2019:1085_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 42.3 kernel was updated to 4.4.176 to receive various
  security and bugfixes.

  The following security bugs were fixed:

  - CVE-2019-9213: expand_downwards in mm/mmap.c lacked a check for the mmap
  minimum address, which made it easier for attackers to exploit kernel
  NULL pointer dereferences on non-SMAP platforms. This is related to a
  capability check for the wrong task (bnc#1128166).

  - CVE-2019-2024: A use-after-free when disconnecting a source was fixed
  which could lead to crashes. bnc#1129179).

  The following non-security bugs were fixed:

  - ax25: fix possible use-after-free (bnc#1012382).

  - block_dev: fix crash on chained bios with O_DIRECT (bsc#1090435).

  - block: do not use bio->bi_vcnt to figure out segment number
  (bsc#1128893).

  - bnxt_re: Fix couple of memory leaks that could lead to IOMMU call traces
  (bsc#1020413).

  - bpf: fix replace_map_fd_with_map_ptr's ldimm64 second imm field
  (bsc#1012382).

  - btrfs: ensure that a DUP or RAID1 block group has exactly two stripes
  (bsc#1128452).

  - ceph: avoid repeatedly adding inode to mdsc->snap_flush_list
  (bsc#1126773).

  - ch: add missing mutex_lock()/mutex_unlock() in ch_release()
  (bsc#1124235).

  - ch: fixup refcounting imbalance for SCSI devices (bsc#1124235).

  - copy_mount_string: Limit string length to PATH_MAX (bsc#1082943).

  - device property: Fix the length used in PROPERTY_ENTRY_STRING()
  (bsc#1129770).

  - Drivers: hv: vmbus: Check for ring when getting debug info (bsc#1126389).

  - drm: Fix error handling in drm_legacy_addctx (bsc#1106929)

  - drm/nouveau/bios/ramcfg: fix missing parentheses when calculating RON
  (bsc#1106929)

  - drm/nouveau/pmu: do not print reply values if exec is false (bsc#1106929)

  - drm/radeon/evergreen_cs: fix missing break in switch statement
  (bsc#1106929)

  - drm/vmwgfx: Do not double-free the mode stored in par->set_mode
  (bsc#1103429)

  - enic: add wq clean up budget (bsc#1075697, bsc#1120691. bsc#1102959).

  - enic: do not overwrite error code (bnc#1012382).

  - fbdev: chipsfb: remove set but not used variable 'size' (bsc#1106929)

  - ibmvnic: Report actual backing device speed and duplex values
  (bsc#1129923).

  - ibmvscsi: Fix empty event pool access during host removal (bsc#1119019).

  - Input: mms114 - fix license module information (bsc#1087092).

  - iommu/dmar: Fix buffer overflow during PCI bus notification
  (bsc#1129237).

  - iommu/io-pgtable-arm-v7s: Only kmemleak_ignore L2 tables (bsc#1129238).

  - iommu/vt-d: Check identity map for hot-added devices (bsc#1129239).

  - iommu/vt-d: Fix NULL pointer reference in intel_svm_bind_mm ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-pdf", rpm:"kernel-docs-pdf~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~4.4.176~96.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
