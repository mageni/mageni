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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0156");
  script_cve_id("CVE-2021-20241", "CVE-2021-20243", "CVE-2021-20244", "CVE-2021-20246");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-25 18:40:00 +0000 (Thu, 25 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0156)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0156");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0156.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28462");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-February/008374.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6SG6MVYKVW7O5POXSG4CGOWDIOAZCWWT/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abydos, abydos, abydos, abydos, blender, blender, converseen, converseen, cuneiform-linux, cuneiform-linux, digikam, digikam, imagemagick, imagemagick, imagemagick, imagemagick, kxstitch, kxstitch, libopenshot, libopenshot, mgba, mgba, pfstools, pfstools, php-imagick, php-imagick, pythonmagick, pythonmagick, sk1, spectacle, spectacle, synfig, synfig, transcode, transcode, uniconvertor, windowmaker, windowmaker, xine-lib1.2, xine-lib1.2, xine-lib1.2, xine-lib1.2, zbar, zbar' package(s) announced via the MGASA-2021-0156 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in ImageMagick in coders/jp2.c. An attacker who submits
a crafted file that is processed by ImageMagick could trigger undefined
behavior in the form of math division by zero. The highest threat from
this vulnerability is to system availability (CVE-2021-20241).

A flaw was found in ImageMagick in MagickCore/resize.c. An attacker who submits
a crafted file that is processed by ImageMagick could trigger undefined
behavior in the form of math division by zero. The highest threat from
this vulnerability is to system availability (CVE-2021-20243).

A flaw was found in ImageMagick in MagickCore/visual-effects.c. An attacker who
submits a crafted file that is processed by ImageMagick could trigger undefined
behavior in the form of math division by zero. The highest threat from this
vulnerability is to system availability (CVE-2021-20244).

A flaw was found in ImageMagick in MagickCore/resample.c. An attacker who
submits a crafted file that is processed by ImageMagick could trigger undefined
behavior in the form of math division by zero. The highest threat from this
vulnerability is to system availability (CVe-2021-20246).

Note that abydos, blender, converseen, cuneiform-linux, digikam, kxxstich,
libopenshot, pfstools, php-imagick, spectacle, synfig, xine-lib1.2, mgba,
windowmaker, zbar and transcode (and tainted conter-parts) have been rebuilt.");

  script_tag(name:"affected", value:"'abydos, abydos, abydos, abydos, blender, blender, converseen, converseen, cuneiform-linux, cuneiform-linux, digikam, digikam, imagemagick, imagemagick, imagemagick, imagemagick, kxstitch, kxstitch, libopenshot, libopenshot, mgba, mgba, pfstools, pfstools, php-imagick, php-imagick, pythonmagick, pythonmagick, sk1, spectacle, spectacle, synfig, synfig, transcode, transcode, uniconvertor, windowmaker, windowmaker, xine-lib1.2, xine-lib1.2, xine-lib1.2, xine-lib1.2, zbar, zbar' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"abydos", rpm:"abydos~0.1.3~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abydos", rpm:"abydos~0.1.3~2.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blender", rpm:"blender~2.79b~14.git20190504.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"converseen", rpm:"converseen~0.9.7.2~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cuneiform-linux", rpm:"cuneiform-linux~1.1.0~15.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"default-windowmaker-desktop", rpm:"default-windowmaker-desktop~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"digikam", rpm:"digikam~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxstitch", rpm:"kxstitch~2.1.1~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxstitch-handbook", rpm:"kxstitch-handbook~2.1.1~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.1-devel", rpm:"lib64abydos0.1-devel~0.1.3~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.1-devel", rpm:"lib64abydos0.1-devel~0.1.3~2.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.1_0", rpm:"lib64abydos0.1_0~0.1.3~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.1_0", rpm:"lib64abydos0.1_0~0.1.3~2.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cuneiform-devel", rpm:"lib64cuneiform-devel~1.1.0~15.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cuneiform0", rpm:"lib64cuneiform0~1.1.0~15.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikam-devel", rpm:"lib64digikam-devel~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamcore6", rpm:"lib64digikamcore6~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamdatabase6", rpm:"lib64digikamdatabase6~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamgui6", rpm:"lib64digikamgui6~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_9", rpm:"lib64magick-7Q16HDRI_9~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_9", rpm:"lib64magick-7Q16HDRI_9~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mgba0.6", rpm:"lib64mgba0.6~0.6.3~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openshot-devel", rpm:"lib64openshot-devel~2.4.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openshot17", rpm:"lib64openshot17~2.4.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pfstools-devel", rpm:"lib64pfstools-devel~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pfstools2", rpm:"lib64pfstools2~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig-devel", rpm:"lib64synfig-devel~1.2.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig0", rpm:"lib64synfig0~1.2.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wings-devel", rpm:"lib64wings-devel~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wings3", rpm:"lib64wings3~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wmaker-devel", rpm:"lib64wmaker-devel~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wmaker1", rpm:"lib64wmaker1~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wraster-devel", rpm:"lib64wraster-devel~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wraster6", rpm:"lib64wraster6~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wutil-devel", rpm:"lib64wutil-devel~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wutil5", rpm:"lib64wutil5~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine1.2-devel", rpm:"lib64xine1.2-devel~1.2.9~9.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine1.2-devel", rpm:"lib64xine1.2-devel~1.2.9~9.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine2", rpm:"lib64xine2~1.2.9~9.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine2", rpm:"lib64xine2~1.2.9~9.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar-devel", rpm:"lib64zbar-devel~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar-gir1.0", rpm:"lib64zbar-gir1.0~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar0", rpm:"lib64zbar0~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbargtk0", rpm:"lib64zbargtk0~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbarqt0", rpm:"lib64zbarqt0~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.1-devel", rpm:"libabydos0.1-devel~0.1.3~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.1-devel", rpm:"libabydos0.1-devel~0.1.3~2.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.1_0", rpm:"libabydos0.1_0~0.1.3~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.1_0", rpm:"libabydos0.1_0~0.1.3~2.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcuneiform-devel", rpm:"libcuneiform-devel~1.1.0~15.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcuneiform0", rpm:"libcuneiform0~1.1.0~15.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikam-devel", rpm:"libdigikam-devel~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamcore6", rpm:"libdigikamcore6~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamdatabase6", rpm:"libdigikamdatabase6~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamgui6", rpm:"libdigikamgui6~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_9", rpm:"libmagick-7Q16HDRI_9~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_9", rpm:"libmagick-7Q16HDRI_9~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmgba0.6", rpm:"libmgba0.6~0.6.3~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot", rpm:"libopenshot~2.4.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot-devel", rpm:"libopenshot-devel~2.4.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot17", rpm:"libopenshot17~2.4.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpfstools-devel", rpm:"libpfstools-devel~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpfstools2", rpm:"libpfstools2~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig-devel", rpm:"libsynfig-devel~1.2.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig0", rpm:"libsynfig0~1.2.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwings-devel", rpm:"libwings-devel~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwings3", rpm:"libwings3~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmaker-devel", rpm:"libwmaker-devel~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmaker1", rpm:"libwmaker1~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwraster-devel", rpm:"libwraster-devel~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwraster6", rpm:"libwraster6~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwutil-devel", rpm:"libwutil-devel~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwutil5", rpm:"libwutil5~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine1.2-devel", rpm:"libxine1.2-devel~1.2.9~9.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine1.2-devel", rpm:"libxine1.2-devel~1.2.9~9.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine2", rpm:"libxine2~1.2.9~9.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine2", rpm:"libxine2~1.2.9~9.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar-devel", rpm:"libzbar-devel~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar-gir1.0", rpm:"libzbar-gir1.0~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar0", rpm:"libzbar0~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbargtk0", rpm:"libzbargtk0~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbarqt0", rpm:"libzbarqt0~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mageia-windowmaker-desktop", rpm:"mageia-windowmaker-desktop~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgba", rpm:"mgba~0.6.3~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgba-qt", rpm:"mgba-qt~0.6.3~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.0.10.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.0.10.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfscalibration", rpm:"pfscalibration~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstmo", rpm:"pfstmo~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools", rpm:"pfstools~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-exr", rpm:"pfstools-exr~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-glview", rpm:"pfstools-glview~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-imgmagick", rpm:"pfstools-imgmagick~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-octave", rpm:"pfstools-octave~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-qt", rpm:"pfstools-qt~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-yuy", rpm:"pfstools-yuy~2.1.0~13.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-imagick", rpm:"php-imagick~3.4.4~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libopenshot", rpm:"python3-libopenshot~2.4.4~2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zbar", rpm:"python3-zbar~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pythonmagick", rpm:"pythonmagick~0.9.19~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"showfoto", rpm:"showfoto~6.1.0~4.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sk1", rpm:"sk1~2.0~0.rc3.5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spectacle", rpm:"spectacle~19.04.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"synfig", rpm:"synfig~1.2.2~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"transcode", rpm:"transcode~1.1.7~23.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uniconvertor", rpm:"uniconvertor~2.0~0.1.rc3_20171226.2.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"windowmaker", rpm:"windowmaker~0.95.8~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine-lib1.2", rpm:"xine-lib1.2~1.2.9~9.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine-lib1.2", rpm:"xine-lib1.2~1.2.9~9.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine1.2-common", rpm:"xine1.2-common~1.2.9~9.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine1.2-common", rpm:"xine1.2-common~1.2.9~9.2.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zbar", rpm:"zbar~0.23~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"abydos", rpm:"abydos~0.2.3~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abydos", rpm:"abydos~0.2.3~4.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abydos-config", rpm:"abydos-config~0.2.3~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abydos-config", rpm:"abydos-config~0.2.3~4.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blender", rpm:"blender~2.83.10~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"converseen", rpm:"converseen~0.9.8.1~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cuneiform-linux", rpm:"cuneiform-linux~1.1.0~18.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"default-windowmaker-desktop", rpm:"default-windowmaker-desktop~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"digikam", rpm:"digikam~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxstitch", rpm:"kxstitch~2.2.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxstitch-handbook", rpm:"kxstitch-handbook~2.2.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.2-devel", rpm:"lib64abydos0.2-devel~0.2.3~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.2-devel", rpm:"lib64abydos0.2-devel~0.2.3~4.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.2_0", rpm:"lib64abydos0.2_0~0.2.3~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.2_0", rpm:"lib64abydos0.2_0~0.2.3~4.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cuneiform-devel", rpm:"lib64cuneiform-devel~1.1.0~18.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cuneiform0", rpm:"lib64cuneiform0~1.1.0~18.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikam-devel", rpm:"lib64digikam-devel~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamcore7.1.0", rpm:"lib64digikamcore7.1.0~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamdatabase7.1.0", rpm:"lib64digikamdatabase7.1.0~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamgui7.1.0", rpm:"lib64digikamgui7.1.0~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_9", rpm:"lib64magick-7Q16HDRI_9~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_9", rpm:"lib64magick-7Q16HDRI_9~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mgba0.8", rpm:"lib64mgba0.8~0.8.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openshot-devel", rpm:"lib64openshot-devel~0.2.5~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openshot19", rpm:"lib64openshot19~0.2.5~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pfstools-devel", rpm:"lib64pfstools-devel~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pfstools2", rpm:"lib64pfstools2~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig-devel", rpm:"lib64synfig-devel~1.2.2~11.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig0", rpm:"lib64synfig0~1.2.2~11.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wings-devel", rpm:"lib64wings-devel~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wings3", rpm:"lib64wings3~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wmaker-devel", rpm:"lib64wmaker-devel~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wmaker1", rpm:"lib64wmaker1~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wraster-devel", rpm:"lib64wraster-devel~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wraster6", rpm:"lib64wraster6~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wutil-devel", rpm:"lib64wutil-devel~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wutil5", rpm:"lib64wutil5~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine1.2-devel", rpm:"lib64xine1.2-devel~1.2.11~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine1.2-devel", rpm:"lib64xine1.2-devel~1.2.11~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine2", rpm:"lib64xine2~1.2.11~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine2", rpm:"lib64xine2~1.2.11~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar-devel", rpm:"lib64zbar-devel~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar-gir1.0", rpm:"lib64zbar-gir1.0~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar0", rpm:"lib64zbar0~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbargtk0", rpm:"lib64zbargtk0~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbarqt0", rpm:"lib64zbarqt0~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.2-devel", rpm:"libabydos0.2-devel~0.2.3~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.2-devel", rpm:"libabydos0.2-devel~0.2.3~4.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.2_0", rpm:"libabydos0.2_0~0.2.3~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.2_0", rpm:"libabydos0.2_0~0.2.3~4.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcuneiform-devel", rpm:"libcuneiform-devel~1.1.0~18.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcuneiform0", rpm:"libcuneiform0~1.1.0~18.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikam-devel", rpm:"libdigikam-devel~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamcore7.1.0", rpm:"libdigikamcore7.1.0~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamdatabase7.1.0", rpm:"libdigikamdatabase7.1.0~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamgui7.1.0", rpm:"libdigikamgui7.1.0~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_9", rpm:"libmagick-7Q16HDRI_9~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_9", rpm:"libmagick-7Q16HDRI_9~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmgba0.8", rpm:"libmgba0.8~0.8.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot", rpm:"libopenshot~0.2.5~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot-devel", rpm:"libopenshot-devel~0.2.5~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot19", rpm:"libopenshot19~0.2.5~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpfstools-devel", rpm:"libpfstools-devel~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpfstools2", rpm:"libpfstools2~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig-devel", rpm:"libsynfig-devel~1.2.2~11.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig0", rpm:"libsynfig0~1.2.2~11.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwings-devel", rpm:"libwings-devel~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwings3", rpm:"libwings3~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmaker-devel", rpm:"libwmaker-devel~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmaker1", rpm:"libwmaker1~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwraster-devel", rpm:"libwraster-devel~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwraster6", rpm:"libwraster6~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwutil-devel", rpm:"libwutil-devel~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwutil5", rpm:"libwutil5~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine1.2-devel", rpm:"libxine1.2-devel~1.2.11~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine1.2-devel", rpm:"libxine1.2-devel~1.2.11~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine2", rpm:"libxine2~1.2.11~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine2", rpm:"libxine2~1.2.11~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar-devel", rpm:"libzbar-devel~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar-gir1.0", rpm:"libzbar-gir1.0~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar0", rpm:"libzbar0~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbargtk0", rpm:"libzbargtk0~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbarqt0", rpm:"libzbarqt0~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mageia-windowmaker-desktop", rpm:"mageia-windowmaker-desktop~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgba", rpm:"mgba~0.8.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgba-qt", rpm:"mgba-qt~0.8.4~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.0.10.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.0.10.62~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfscalibration", rpm:"pfscalibration~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstmo", rpm:"pfstmo~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools", rpm:"pfstools~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-exr", rpm:"pfstools-exr~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-glview", rpm:"pfstools-glview~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-imgmagick", rpm:"pfstools-imgmagick~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-octave", rpm:"pfstools-octave~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-qt", rpm:"pfstools-qt~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-yuy", rpm:"pfstools-yuy~2.1.0~20.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-imagick", rpm:"php-imagick~3.4.5~0.git20201230.2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libopenshot", rpm:"python3-libopenshot~0.2.5~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zbar", rpm:"python3-zbar~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pythonmagick", rpm:"pythonmagick~0.9.19~10.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"showfoto", rpm:"showfoto~7.1.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spectacle", rpm:"spectacle~20.12.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"synfig", rpm:"synfig~1.2.2~11.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"transcode", rpm:"transcode~1.1.7~29.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"windowmaker", rpm:"windowmaker~0.95.9~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine-lib1.2", rpm:"xine-lib1.2~1.2.11~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine-lib1.2", rpm:"xine-lib1.2~1.2.11~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine1.2-common", rpm:"xine1.2-common~1.2.11~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine1.2-common", rpm:"xine1.2-common~1.2.11~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zbar", rpm:"zbar~0.23.1~5.1.mga8", rls:"MAGEIA8"))) {
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
