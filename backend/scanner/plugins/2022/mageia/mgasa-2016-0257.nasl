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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0257");
  script_cve_id("CVE-2016-5118", "CVE-2016-5841", "CVE-2016-5842");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2016-0257)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0257");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0257.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18598");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q2/432");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/06/25/3");
  script_xref(name:"URL", value:"http://git.imagemagick.org/repos/ImageMagick/blob/ImageMagick-6/ChangeLog");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3591");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'converseen, cuneiform-linux, imagemagick, inkscape, k3d, kcm-grub2, kxstitch, performous, perl-Image-SubImageFind, pfstools, pstoedit, pythonmagick, synfig, vdr-plugin-skinelchi, vdr-plugin-skinenigmang' package(s) announced via the MGASA-2016-0257 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated imagemagick package fixes security vulnerabilities:

The OpenBlob function in blob.c in ImageMagick allows remote attackers to
execute arbitrary code via a <pipe> (pipe) character at the start of a filename
(CVE-2016-5118).

Integer overflow in MagickCore/profile.c (CVE-2016-5841).

Buffer overread in MagickCore/property.c (CVE-2016-5842).

Also, several packages have been rebuilt to use the updated Magick++-6.Q16
library. These include converseen, cuneiform-linux, inkscape, k3d, kcm-grub2,
kxstitch, performous, perl-Image-SubImageFind, pfstools, pstoedit,
pythonmagick, synfig, vdr-plugin-skinelchi, and vdr-plugin-skinenigmang.");

  script_tag(name:"affected", value:"'converseen, cuneiform-linux, imagemagick, inkscape, k3d, kcm-grub2, kxstitch, performous, perl-Image-SubImageFind, pfstools, pstoedit, pythonmagick, synfig, vdr-plugin-skinelchi, vdr-plugin-skinenigmang' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"converseen", rpm:"converseen~0.8.3~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cuneiform-linux", rpm:"cuneiform-linux~1.1.0~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"inkscape", rpm:"inkscape~0.91~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"k3d", rpm:"k3d~0.8.0.2~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"k3d-devel", rpm:"k3d-devel~0.8.0.2~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcm-grub2", rpm:"kcm-grub2~0.5.8~12.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxstitch", rpm:"kxstitch~1.2.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxstitch-handbook", rpm:"kxstitch-handbook~1.2.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cuneiform-devel", rpm:"lib64cuneiform-devel~1.1.0~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cuneiform0", rpm:"lib64cuneiform0~1.1.0~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-6Q16_6", rpm:"lib64magick++-6Q16_6~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-6Q16_2", rpm:"lib64magick-6Q16_2~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pfstools-devel", rpm:"lib64pfstools-devel~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pfstools1.2_0", rpm:"lib64pfstools1.2_0~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pstoedit-devel", rpm:"lib64pstoedit-devel~3.62~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pstoedit0", rpm:"lib64pstoedit0~3.62~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig-devel", rpm:"lib64synfig-devel~0.64.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig0", rpm:"lib64synfig0~0.64.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcuneiform-devel", rpm:"libcuneiform-devel~1.1.0~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcuneiform0", rpm:"libcuneiform0~1.1.0~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-6Q16_6", rpm:"libmagick++-6Q16_6~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-6Q16_2", rpm:"libmagick-6Q16_2~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpfstools-devel", rpm:"libpfstools-devel~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpfstools1.2_0", rpm:"libpfstools1.2_0~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpstoedit-devel", rpm:"libpstoedit-devel~3.62~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpstoedit0", rpm:"libpstoedit0~3.62~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig-devel", rpm:"libsynfig-devel~0.64.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig0", rpm:"libsynfig0~0.64.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"performous", rpm:"performous~0.8.0~0.20141015.2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.9.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-SubImageFind", rpm:"perl-Image-SubImageFind~0.30.0~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools", rpm:"pfstools~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-exr", rpm:"pfstools-exr~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-gdal", rpm:"pfstools-gdal~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-glview", rpm:"pfstools-glview~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-imgmagick", rpm:"pfstools-imgmagick~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-octave", rpm:"pfstools-octave~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-qt", rpm:"pfstools-qt~1.8.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pstoedit", rpm:"pstoedit~3.62~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pythonmagick", rpm:"pythonmagick~0.9.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"synfig", rpm:"synfig~0.64.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-plugin-skinelchi", rpm:"vdr-plugin-skinelchi~0.2.8~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-plugin-skinenigmang", rpm:"vdr-plugin-skinenigmang~0.1.2~8.1.mga5", rls:"MAGEIA5"))) {
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
