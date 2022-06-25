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
  script_oid("1.3.6.1.4.1.25623.1.0.853870");
  script_version("2021-06-17T06:11:17+0000");
  script_cve_id("CVE-2021-29155", "CVE-2021-29650");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-06-17 10:43:15 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 03:01:52 +0000 (Thu, 17 Jun 2021)");
  script_name("openSUSE: Security Advisory for the (openSUSE-SU-2021:0873-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0873-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/THW3Z3CCX5HRFD2KJ3A4TDO27FGBEKNN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2021:0873-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 RT kernel was updated to receive various
     security and bugfixes.


     The following security bugs were fixed:

  - CVE-2021-29650: Fixed an issue with the netfilter subsystem that allowed
       attackers to cause a denial of service (panic) because
       net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h lack a
       full memory barrier upon the assignment of a new table value
       (bnc#1184208).

  - CVE-2021-29155: Fixed an issue that was discovered in
       kernel/bpf/verifier.c that performs undesirable out-of-bounds
       speculation on pointer arithmetic, leading to side-channel attacks that
       defeat Spectre mitigations and obtain sensitive information from kernel
       memory. Specifically, for sequences of pointer arithmetic operations,
       the pointer modification performed by the first operation was not
       correctly accounted for when restricting subsequent operations
       (bnc#1184942).

     The following non-security bugs were fixed:

  - ACPI: CPPC: Replace cppc_attr with kobj_attribute (git-fixes).

  - ALSA: core: remove redundant spin_lock pair in snd_card_disconnect
       (git-fixes).

  - ALSA: emu8000: Fix a use after free in snd_emu8000_create_mixer
       (git-fixes).

  - ALSA: hda/cirrus: Add error handling into CS8409 I2C functions
       (git-fixes).

  - ALSA: hda/cirrus: Add Headphone and Headset MIC Volume Control
       (git-fixes).

  - ALSA: hda/cirrus: Add jack detect interrupt support from CS42L42
       companion codec (git-fixes).

  - ALSA: hda/cirrus: Add support for CS8409 HDA bridge and CS42L42
       companion codec (git-fixes).

  - ALSA: hda/cirrus: Cleanup patch_cirrus.c code (git-fixes).

  - ALSA: hda/cirrus: Fix CS42L42 Headset Mic volume control name
       (git-fixes).

  - ALSA: hda/cirrus: Make CS8409 driver more generic by using fixups
       (git-fixes).

  - ALSA: hda/cirrus: Set Initial DMIC volume for Bullseye to -26 dB
       (git-fixes).

  - ALSA: hda/cirrus: Use CS8409 filter to fix abnormal sounds on Bullseye
       (git-fixes).

  - ALSA: hda/realtek: Add quirk for Intel Clevo PCx0Dx (git-fixes).

  - ALSA: hda/realtek: fix mic boost on Intel NUC 8 (git-fixes).

  - ALSA: hda/realtek: fix static noise on ALC285 Lenovo laptops (git-fixes).

  - ALSA: hda/realtek: GA503 use same quirks as GA401 (git-fixes).

  - ALSA: hda/realtek - Headset Mic issue on HP platform (git-fixes).

  - ALSA: hda/realtek: Remove redundant entry for ALC861 Haier/Uniwill
       devices (git-fixes).

  - ALSA: hda/realtek: Re-order ALC2 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt_debug", rpm:"cluster-md-kmp-rt_debug~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt_debug-debuginfo", rpm:"cluster-md-kmp-rt_debug-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt_debug", rpm:"dlm-kmp-rt_debug~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt_debug-debuginfo", rpm:"dlm-kmp-rt_debug-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt_debug", rpm:"gfs2-kmp-rt_debug~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt_debug-debuginfo", rpm:"gfs2-kmp-rt_debug-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra-debuginfo", rpm:"kernel-rt-extra-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-extra", rpm:"kernel-rt_debug-extra~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-extra-debuginfo", rpm:"kernel-rt_debug-extra-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt-debuginfo", rpm:"kselftests-kmp-rt-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt_debug", rpm:"kselftests-kmp-rt_debug~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt_debug-debuginfo", rpm:"kselftests-kmp-rt_debug-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt_debug", rpm:"ocfs2-kmp-rt_debug~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt_debug-debuginfo", rpm:"ocfs2-kmp-rt_debug-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt-debuginfo", rpm:"reiserfs-kmp-rt-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt_debug", rpm:"reiserfs-kmp-rt_debug~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt_debug-debuginfo", rpm:"reiserfs-kmp-rt_debug-debuginfo~5.3.18~lp152.3.11.1", rls:"openSUSELeap15.2"))) {
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