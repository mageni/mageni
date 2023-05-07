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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1970.2");
  script_cve_id("CVE-2016-3977", "CVE-2018-11490", "CVE-2019-15133");
  script_tag(name:"creation_date", value:"2023-04-25 04:17:30 +0000 (Tue, 25 Apr 2023)");
  script_version("2023-04-25T10:19:16+0000");
  script_tag(name:"last_modification", value:"2023-04-25 10:19:16 +0000 (Tue, 25 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-03 19:05:00 +0000 (Fri, 03 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1970-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1970-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231970-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'giflib' package(s) announced via the SUSE-SU-2023:1970-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for giflib fixes the following issues:

CVE-2019-15133: Fixed a divide-by-zero exception in the decoder function DGifSlurp in dgif_lib.c if the height field of the ImageSize data structure is equal to zero (bsc#1146299).
CVE-2018-11490: Fixed a heap-based buffer overflow in DGifDecompressLine function in dgif_lib.c (bsc#1094832).
CVE-2016-3977: Fixed a heap buffer overflow in gif2rgb (bsc#974847).

Update to version 5.2.1

In gifbuild.c, avoid a core dump on no color map.
Restore inadvertently removed library version numbers in Makefile.

Changes in version 5.2.0

The undocumented and deprecated GifQuantizeBuffer() entry point
 has been moved to the util library to reduce libgif size and attack
 surface. Applications needing this function are couraged to link the
 util library or make their own copy.
The following obsolete utility programs are no longer installed:
 gifecho, giffilter, gifinto, gifsponge. These were either installed in
 error or have been obsolesced by modern image-transformmation tools
 like ImageMagick convert. They may be removed entirely in a future
 release.
Address SourceForge issue #136: Stack-buffer-overflow in gifcolor.c:84 Address SF bug #134: Giflib fails to slurp significant number of gifs Apply SPDX convention for license tagging.

Changes in version 5.1.9

The documentation directory now includes an HTMlified version of the
 GIF89 standard, and a more detailed description of how LZW compression
 is applied to GIFs.
Address SF bug #129: The latest version of giflib cannot be build on windows.
Address SF bug #126: Cannot compile giflib using c89

Changes in version 5.1.8

Address SF bug #119: MemorySanitizer: FPE on unknown address (CVE-2019-15133 bsc#1146299)
Address SF bug #125: 5.1.7: xmlto is still required for tarball Address SF bug #124: 5.1.7: ar invocation is not crosscompile compatible Address SF bug #122: 5.1.7 installs manpages to wrong directory Address SF bug #121: make: getversion: Command not found Address SF bug #120: 5.1.7 does not build a proper library - no

Changes in version 5.1.7
 * Correct a minor packaging error (superfluous symlinks) in the 5.1.6 tarballs.
Changes in version 5.1.6
 * Fix library installation in the Makefile.
Changes in version 5.1.5
 * Fix SF bug #114: Null dereferences in main() of gifclrmp
 * Fix SF bug #113: Heap Buffer Overflow-2 in function DGifDecompressLine()
 in cgif.c. This had been assigned (CVE-2018-11490 bsc#1094832).
 * Fix SF bug #111: segmentation fault in PrintCodeBlock
 * Fix SF bug #109: Segmentation fault of giftool reading a crafted file
 * Fix SF bug #107: Floating point exception in giftext utility
 * Fix SF bug #105: heap buffer overflow in DumpScreen2RGB in gif2rgb.c:317
 * Fix SF bug #104: Ineffective bounds check in DGifSlurp
 * Fix SF bug #103: GIFLIB 5.1.4: DGifSlurp fails on empty comment
 * Fix SF bug #87: Heap buffer overflow in 5.1.2 (gif2rgb). (CVE-2016-3977 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'giflib' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"giflib-debugsource", rpm:"giflib-debugsource~5.2.1~150000.4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~5.2.1~150000.4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7", rpm:"libgif7~5.2.1~150000.4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-debuginfo", rpm:"libgif7-debuginfo~5.2.1~150000.4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"giflib-debugsource", rpm:"giflib-debugsource~5.2.1~150000.4.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~5.2.1~150000.4.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7", rpm:"libgif7~5.2.1~150000.4.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-debuginfo", rpm:"libgif7-debuginfo~5.2.1~150000.4.8.1", rls:"SLES15.0SP2"))) {
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
