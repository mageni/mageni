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
  script_oid("1.3.6.1.4.1.25623.1.0.853913");
  script_version("2021-07-23T08:38:39+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:03:07 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for libopenmpt (openSUSE-SU-2021:1914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1914-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3KSE7XFTNSSNEOWC7CY5BJTMT7YMJ54W");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libopenmpt'
  package(s) announced via the openSUSE-SU-2021:1914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libopenmpt fixes the following issues:

     Various bugfix and stability issues were fixed, some of those might have
     security impact.

     libopenmpt was updated to 0.3.28:

  * Fixed excessive memory consumption with malformed files in various
       formats.

     Changes in 0.3.27:

  * AMS: Avoid allocating excessive amount of memory for compressed song
       message in malformed files.

  * S3M: Some samples were imported with a too high sample rate if module
       was saved with Scream Tracker 3.

     Changes in 0.3.26:

  * DMF: Improve import of finetune effect with parameters larger than +/-15.

     Changes in 0.3.25:

  * AMS: An upper bound for uncompressed sample size is now established to
       avoid memory exhaustion from malformed files.

  * MO3: Avoid certain ModPlug hacks from being fixed up twice, which could
       lead to e.g. very narrow pan swing range for old OpenMPT IT files saved
       with a recent MO3 encoder version.

  * IMF: Instrument sample mapping was off by one octave, notable in the
       guitar part of Astaris by Karsten Koch.

  * PLM: Percentage offset (Mxx) was slightly off.

     Changes in 0.3.24:

  * PP20: The first few bytes of some files were not decompressed properly,
       making some files unplayable (depending on the
       original format).

     Changes in 0.3.23:

  * IT: Global volume slides with both nibbles set preferred the slide
       up nibble over the slide down nibble in old OpenMPT versions,
       unlike other slides. Such old files are now imported correctly again.

  * IT: Fixed an edge case where, if the filter hit full cutoff / no
       resonance on the first tick of a row where a new delayed note would be
       triggered, the filter would be disabled even though it should stay
       active. Fixes trace.it by maddie.

  * XM: Out-of-range arpeggio clamping behaviour broke in OpenMPT
       1.23.05.00. The arpeggios in Binary World by Dakota now play correctly
       again.

  * S3M: Support old-style sample pre-amp value in very early S3M files.

  * S3M: Only force-enable fast slides for files ST 3.00. Previously, any
       S3M file made with an ST3 version older than 3.20 enabled them.

  * M15: Improve tracker detection heuristics to never assume SoundTracker
       2.0 if there is a huge number of Dxx commands, as that is a definite
       hint that they should be treated as volume slides. Fixes Monty On The
       Run by Master Blaster.

     Changes in 0.3.22:

  * IT: Disable retrigger with short no ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'libopenmpt' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libmodplug-devel", rpm:"libmodplug-devel~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodplug1", rpm:"libmodplug1~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodplug1-debuginfo", rpm:"libmodplug1-debuginfo~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-debugsource", rpm:"libopenmpt-debugsource~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-devel", rpm:"libopenmpt-devel~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt0", rpm:"libopenmpt0~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt0-debuginfo", rpm:"libopenmpt0-debuginfo~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt_modplug1", rpm:"libopenmpt_modplug1~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt_modplug1-debuginfo", rpm:"libopenmpt_modplug1-debuginfo~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpt123", rpm:"openmpt123~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpt123-debuginfo", rpm:"openmpt123-debuginfo~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodplug1-32bit", rpm:"libmodplug1-32bit~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodplug1-32bit-debuginfo", rpm:"libmodplug1-32bit-debuginfo~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt0-32bit", rpm:"libopenmpt0-32bit~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt0-32bit-debuginfo", rpm:"libopenmpt0-32bit-debuginfo~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt_modplug1-32bit", rpm:"libopenmpt_modplug1-32bit~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt_modplug1-32bit-debuginfo", rpm:"libopenmpt_modplug1-32bit-debuginfo~0.3.28~2.13.1", rls:"openSUSELeap15.3"))) {
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