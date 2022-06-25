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
  script_oid("1.3.6.1.4.1.25623.1.0.854652");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2016-3977", "CVE-2018-11490", "CVE-2019-15133");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2022-05-17 12:07:26 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for giflib (SUSE-SU-2022:1565-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1565-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FPIGWCTPLVFBHKIUGSLGA272LIOBE6RC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'giflib'
  package(s) announced via the SUSE-SU-2022:1565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for giflib fixes the following issues:

  - CVE-2019-15133: Fixed a divide-by-zero exception in the decoder function
       DGifSlurp in dgif_lib.c if the height field of the ImageSize data
       structure is equal to zero (bsc#1146299).

  - CVE-2018-11490: Fixed a heap-based buffer overflow in DGifDecompressLine
       function in dgif_lib.c (bsc#1094832).

  - CVE-2016-3977: Fixed a heap buffer overflow in gif2rgb (bsc#974847).
  Update to version 5.2.1

  * In gifbuild.c, avoid a core dump on no color map.

  * Restore inadvertently removed library version numbers in Makefile.
  Changes in version 5.2.0

  * The undocumented and deprecated GifQuantizeBuffer() entry point has
         been moved to the util library to reduce libgif size and attack
         surface. Applications needing this function are couraged to link the
         util library or make their own copy.

  * The following obsolete utility programs are no longer installed:
         gifecho, giffilter, gifinto, gifsponge. These were either installed in
         error or have been obsolesced by modern image-transformmation tools
         like ImageMagick convert. They may be removed entirely in a future
         release.

  * Address SourceForge issue #136: Stack-buffer-overflow in gifcolor.c:84

  * Address SF bug #134: Giflib fails to slurp significant number of gifs

  * Apply SPDX convention for license tagging.
  Changes in version 5.1.9

  * The documentation directory now includes an HTMlified version of the
         GIF89 standard, and a more detailed description of how LZW compression
         is applied to GIFs.

  * Address SF bug #129: The latest version of giflib cannot be build on
         windows.

  * Address SF bug #126: Cannot compile giflib using c89
  Changes in version 5.1.8

  * Address SF bug #119: MemorySanitizer: FPE on unknown address
         (CVE-2019-15133 bsc#1146299)

  * Address SF bug #125: 5.1.7: xmlto is still required for tarball

  * Address SF bug #124: 5.1.7: ar invocation is not crosscompile
         compatible

  * Address SF bug #122: 5.1.7 installs manpages to wrong directory

  * Address SF bug #121: make: getversion: Command not found

  * Address SF bug #120: 5.1.7 does not build a proper library - no
  Changes in version 5.1.7

  * Correct a minor packaging error (superfluous symlinks) in the 5.1.6
         tarballs.
  Changes in version 5.1.6

  * Fix library installation in the Makefile.
  Changes in version 5.1.5

  * Fix SF bug #114: Null dereferences in m ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'giflib' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"giflib-debugsource", rpm:"giflib-debugsource~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-progs", rpm:"giflib-progs~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-progs-debuginfo", rpm:"giflib-progs-debuginfo~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7", rpm:"libgif7~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-debuginfo", rpm:"libgif7-debuginfo~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel-32bit", rpm:"giflib-devel-32bit~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-32bit", rpm:"libgif7-32bit~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-32bit-debuginfo", rpm:"libgif7-32bit-debuginfo~5.2.1~150000.4.8.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"giflib-debugsource", rpm:"giflib-debugsource~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-progs", rpm:"giflib-progs~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-progs-debuginfo", rpm:"giflib-progs-debuginfo~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7", rpm:"libgif7~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-debuginfo", rpm:"libgif7-debuginfo~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel-32bit", rpm:"giflib-devel-32bit~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-32bit", rpm:"libgif7-32bit~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-32bit-debuginfo", rpm:"libgif7-32bit-debuginfo~5.2.1~150000.4.8.1", rls:"openSUSELeap15.3"))) {
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